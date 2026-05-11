/**
 * Sanctuary v1.3 WP-V1.3-3 Omega-3 Workflow State Tracker.
 *
 * Tracks the most-recently-observed `state` for each workflow_id so
 * the list-route handler can emit a `coordination_workflow_state_changed`
 * audit event when a workflow transitions (e.g., from `in_progress`
 * to `stalled`). Coordination state changes are operator-relevant
 * signals; the tracker makes them legible without coupling the pure
 * grouper to side effects.
 *
 * The tracker is fortress-scoped: callers construct one instance per
 * `HandoffLog` (which is itself per-fortress). Different fortresses
 * cannot leak state transitions into each other's audit logs because
 * each fortress has its own tracker holding its own snapshot map.
 *
 * Sovereignty invariants:
 *
 *   - No outbound surface. The tracker is a stateful diff observer
 *     over input from `groupHandoffsIntoWorkflows()`; it never reaches
 *     the network and never reads storage on its own.
 *   - No LLM call.
 *   - Pure modulo the in-memory snapshot map. `observe()` is the only
 *     mutating call.
 *
 * Threading: callers MUST NOT share a single tracker between
 * concurrent observers; the route handler in `handoff-routes.ts`
 * already holds the dispatch-side lock via the request lifecycle.
 */

import type { Workflow, WorkflowState } from "./workflow-grouper.js";

/**
 * One emitted state-change event. The route handler audit-emits this
 * as `coordination_workflow_state_changed` and (optionally) pushes it
 * to SSE subscribers so the dashboard tab updates without a poll.
 */
export interface WorkflowStateChange {
  workflow_id: string;
  previous_state: WorkflowState | "unobserved";
  new_state: WorkflowState;
  observed_at: string;
}

export interface WorkflowStateTrackerOptions {
  /**
   * Wall-clock provider for the emitted `observed_at` timestamp.
   * Defaults to a fresh `Date.now()` on each emit. Tests inject a
   * fixed clock so audit emissions stay deterministic.
   */
  now?: () => Date;
}

export class WorkflowStateTracker {
  private readonly states = new Map<string, WorkflowState>();
  private readonly now: () => Date;

  constructor(opts?: WorkflowStateTrackerOptions) {
    this.now = opts?.now ?? (() => new Date());
  }

  /**
   * Diff the supplied workflow list against the last-observed states.
   * Returns the set of transitions detected this call; the tracker
   * mutates its internal map to reflect the new states.
   *
   * Transitions emitted:
   *   - First observation of a workflow (`previous_state` is the
   *     sentinel `unobserved`). Lets the route handler audit-emit
   *     the initial state so the operator sees workflows as they
   *     surface, not only when they change.
   *   - Subsequent observation where `previous_state !== new_state`.
   */
  observe(workflows: ReadonlyArray<Workflow>): WorkflowStateChange[] {
    const out: WorkflowStateChange[] = [];
    const observedAt = this.now().toISOString();
    for (const wf of workflows) {
      const prior = this.states.get(wf.workflow_id);
      if (prior === undefined) {
        out.push({
          workflow_id: wf.workflow_id,
          previous_state: "unobserved",
          new_state: wf.state,
          observed_at: observedAt,
        });
        this.states.set(wf.workflow_id, wf.state);
        continue;
      }
      if (prior !== wf.state) {
        out.push({
          workflow_id: wf.workflow_id,
          previous_state: prior,
          new_state: wf.state,
          observed_at: observedAt,
        });
        this.states.set(wf.workflow_id, wf.state);
      }
    }
    return out;
  }

  /**
   * Drop a workflow's recorded state. Surfaced for tests + future
   * "operator dismissed this workflow" affordance; not currently
   * called by the production wiring.
   */
  forget(workflowId: string): void {
    this.states.delete(workflowId);
  }

  /** Reset the tracker. Tests use this between runs. */
  reset(): void {
    this.states.clear();
  }

  /** Read-only view of the current snapshot. Useful for diagnostics. */
  snapshot(): ReadonlyMap<string, WorkflowState> {
    return new Map(this.states);
  }
}
