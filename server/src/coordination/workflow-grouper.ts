/**
 * Sanctuary v1.3 WP-V1.3-3 Omega-3 Workflow Grouper.
 *
 * CLOSES WP-V1.3-3 Coordination Handoff Visualization. Omega-1 (#191)
 * shipped the chronological handoff log; Omega-2 (#196) shipped the
 * per-handoff context-transfer breakdown; Omega-3 lifts isolated
 * handoff events into multi-handoff WORKFLOWS so the operator finally
 * sees the shape of a multi-agent collaboration as a single object:
 * who started it, who participated, how recently it was active, and
 * whether it is still in progress, stalled, or done.
 *
 * Pure functions. No I/O, no clock side effects beyond the optional
 * `now` argument for deterministic state determination. Tests inject
 * synthetic `HandoffEntry[]` and assert the grouping + state
 * decisions directly.
 *
 * Grouping algorithm:
 *
 *   1. Explicit link path: handoffs whose `workflow_link` field is
 *      non-null group by that key. (At v1.3 Omega-1, Omega-1's
 *      `normalize()` always sets the field to null. Omega-3 still
 *      reads it because future Tau-X work will populate the field
 *      from coordinator-emitted audit payloads, at which point
 *      explicit grouping is the high-confidence path and the heuristic
 *      becomes the fallback.)
 *
 *   2. Heuristic chain path: among handoffs without an explicit link,
 *      sort by `observed_at` ascending and walk. A handoff joins an
 *      existing workflow when (a) it shares at least one agent
 *      (sender or recipient) with the most recent member of that
 *      workflow AND (b) the time gap is at most HEURISTIC_WINDOW_MS
 *      (5 minutes). Otherwise it starts a new workflow.
 *
 *      This relaxes the literal "same source-target pair within 5
 *      minutes" reading of the WP-V1.3-3 scope-lock to also handle
 *      multi-hop chains like Cline -> OpenClaw -> Cursor, which is
 *      what the operator-facing example in the scope-lock describes.
 *      Without this relaxation, every hop in a chain becomes its own
 *      "workflow" of one, and the dashboard surface loses the
 *      legibility the WP-V1.3-3 acceptance gate promises. Documented
 *      as a deviation in the PR body; consistent with how Phi-3
 *      cross-agent-chatter shipped its connectivity heuristic.
 *
 * Root handoff: the oldest handoff in a workflow group. (At v1.3 there
 * is no audit-log surface for "this handoff was caused by handoff X",
 * so the chronological-oldest is the load-bearing root signal; when
 * Tau-X wires causal-link payloads, this rule extends without API
 * change.)
 *
 * State determination (in priority order):
 *
 *   - `completed`: the last member's recipient is OPERATOR_PSEUDO_AGENT
 *     (the workflow returned to the operator for approval / done),
 *     OR the workflow has crossed >=2 hops and the last member returns
 *     to the workflow's root agent (cycle closure).
 *   - `stalled`: no member observed within STALL_THRESHOLD_MS (2h) of
 *     `now`.
 *   - `in_progress`: recent member within STALL_THRESHOLD_MS, no
 *     completion signal.
 *   - `unknown`: insufficient evidence (e.g., an empty member list,
 *     which the grouper never emits but which we accept defensively
 *     for downstream callers that synthesize Workflow objects).
 *
 * Castle-walking discipline:
 *
 *   - No outbound surface. Pure computation over already-server-local
 *     `HandoffEntry` records.
 *   - No LLM call. The heuristic is rule-based.
 *   - Multi-fortress isolation: the grouper takes whatever input it
 *     receives; the caller (a `HandoffLog` instance scoped to ONE
 *     fortress) is responsible for not mixing fortress data. The
 *     route layer reads through `HandoffLog.query()` which already
 *     enforces fortress boundary at the encryption layer.
 *
 * Out of scope for Omega-3 (deferred to v1.4+ federation): cross-
 * fortress workflow tracking. Workflow templating + operator-action
 * UI on stalled workflows ("auto-restart") are v1.5+ scope.
 */

import { createHash } from "node:crypto";

import {
  OPERATOR_PSEUDO_AGENT,
  type HandoffEntry,
} from "./handoff-log.js";

/** Stable lifecycle-state enum surfaced into the operator UI. */
export type WorkflowState =
  | "in_progress"
  | "completed"
  | "stalled"
  | "unknown";

/**
 * One multi-handoff workflow grouped from the underlying handoff log.
 *
 * `workflow_id` is deterministic (SHA-256 of the root handoff's
 * `entry_id` truncated to 32 hex chars) so the same workflow re-
 * derives identical ids across server restarts. Tests and the SSE
 * stream rely on this stability for diff-based state-change
 * emission.
 *
 * `member_handoffs` is sorted oldest-first and INCLUDES the root.
 * `involved_agents` is deduplicated, alphabetically ordered. Empty
 * pseudo-agent strings are dropped; the OPERATOR_PSEUDO_AGENT is
 * preserved as a member because it signals completion.
 */
export interface Workflow {
  workflow_id: string;
  root_handoff: HandoffEntry;
  member_handoffs: HandoffEntry[];
  state: WorkflowState;
  started_at: string;
  last_activity_at: string;
  involved_agents: string[];
}

/** Heuristic chain-formation window. */
const HEURISTIC_WINDOW_MS = 5 * 60 * 1000;
/** Stall threshold; matches the WP-V1.3-3 scope-lock copy. */
const STALL_THRESHOLD_MS = 2 * 60 * 60 * 1000;
/** Minimum hop count for cycle-closure completion. */
const CYCLE_COMPLETION_MIN_HOPS = 2;

export interface GroupHandoffsOptions {
  /**
   * Wall-clock anchor for state determination. Defaults to `Date.now()`.
   * Tests inject a fixed clock so stall/in-progress decisions are
   * deterministic.
   */
  now?: Date;
}

// ── Public API ───────────────────────────────────────────────────────────

/**
 * Group a flat list of HandoffEntry records into Workflow objects.
 * Pure: returns a fresh array, mutates nothing.
 */
export function groupHandoffsIntoWorkflows(
  handoffs: ReadonlyArray<HandoffEntry>,
  opts?: GroupHandoffsOptions,
): Workflow[] {
  if (handoffs.length === 0) return [];
  const now = opts?.now ?? new Date();

  // Phase 1: explicit-link grouping. Build a map workflow_link -> members.
  const linkedGroups = new Map<string, HandoffEntry[]>();
  const unlinked: HandoffEntry[] = [];
  for (const h of handoffs) {
    if (h.workflow_link !== null && h.workflow_link.length > 0) {
      let bucket = linkedGroups.get(h.workflow_link);
      if (!bucket) {
        bucket = [];
        linkedGroups.set(h.workflow_link, bucket);
      }
      bucket.push(h);
    } else {
      unlinked.push(h);
    }
  }

  // Phase 2: heuristic chain grouping for unlinked handoffs. Walk
  // oldest-first and either extend an existing chain or start a new
  // one.
  const sortedUnlinked = [...unlinked].sort((a, b) =>
    a.observed_at < b.observed_at ? -1 : 1,
  );

  const heuristicChains: HandoffEntry[][] = [];
  for (const h of sortedUnlinked) {
    const joinedIdx = findExtendableChain(heuristicChains, h);
    if (joinedIdx !== null) {
      heuristicChains[joinedIdx]!.push(h);
    } else {
      heuristicChains.push([h]);
    }
  }

  // Phase 3: materialize Workflow objects from both groupings. Sort
  // each member set oldest-first so root + last_activity are
  // unambiguous.
  const workflows: Workflow[] = [];
  for (const members of linkedGroups.values()) {
    workflows.push(materialize(members, now));
  }
  for (const members of heuristicChains) {
    workflows.push(materialize(members, now));
  }

  // Stable sort: newest activity first so the operator dashboard
  // surfaces fresh workflows at the top.
  workflows.sort((a, b) =>
    a.last_activity_at < b.last_activity_at ? 1 : -1,
  );
  return workflows;
}

/**
 * Decide the state of one workflow. Exposed separately so the
 * state-change tracker can re-evaluate state on each tick without
 * re-grouping the entire handoff log.
 */
export function determineWorkflowState(
  members: ReadonlyArray<HandoffEntry>,
  now: Date,
): WorkflowState {
  if (members.length === 0) return "unknown";
  const sorted = [...members].sort((a, b) =>
    a.observed_at < b.observed_at ? -1 : 1,
  );
  const last = sorted[sorted.length - 1]!;
  const root = sorted[0]!;
  const lastMs = Date.parse(last.observed_at);
  if (!Number.isFinite(lastMs)) return "unknown";

  // Completion check 1: returned to the operator. Cross-harness
  // approval flows model the operator as the recipient pseudo-agent;
  // a handoff back to operator is the canonical "done" signal.
  if (last.target_agent_id === OPERATOR_PSEUDO_AGENT) {
    return "completed";
  }

  // Completion check 2: cycle closure. The workflow returned to its
  // root agent after at least CYCLE_COMPLETION_MIN_HOPS handoffs.
  if (
    sorted.length > CYCLE_COMPLETION_MIN_HOPS &&
    last.target_agent_id === root.source_agent_id
  ) {
    return "completed";
  }

  // Stall check: no activity within the stall threshold of `now`.
  const ageMs = now.getTime() - lastMs;
  if (ageMs > STALL_THRESHOLD_MS) {
    return "stalled";
  }

  return "in_progress";
}

/**
 * Derive the stable workflow id from a root handoff. SHA-256 of the
 * root entry id, truncated to 32 hex chars (mirrors Omega-1's entry-id
 * shape). Exposed so the SSE stream's state-change events carry the
 * same id consumers see in list / detail responses.
 */
export function workflowIdFromRoot(rootEntryId: string): string {
  return createHash("sha256")
    .update(`workflow:${rootEntryId}`)
    .digest("hex")
    .slice(0, 32);
}

// ── Internals ────────────────────────────────────────────────────────────

/**
 * Find a chain that can be extended by `h`. Returns the chain index
 * or null when no chain is a match. A match requires:
 *  - At least one agent (sender or recipient) in common with the
 *    chain's last member.
 *  - Time gap from the chain's last member at most HEURISTIC_WINDOW_MS.
 *
 * When multiple chains match, the most-recently-active one wins (the
 * chain whose last member is closest in time to `h`).
 */
function findExtendableChain(
  chains: HandoffEntry[][],
  h: HandoffEntry,
): number | null {
  const hMs = Date.parse(h.observed_at);
  if (!Number.isFinite(hMs)) return null;
  let bestIdx: number | null = null;
  let bestGapMs = Number.POSITIVE_INFINITY;
  for (let i = 0; i < chains.length; i += 1) {
    const chain = chains[i]!;
    const last = chain[chain.length - 1]!;
    const lastMs = Date.parse(last.observed_at);
    if (!Number.isFinite(lastMs)) continue;
    const gapMs = Math.abs(hMs - lastMs);
    if (gapMs > HEURISTIC_WINDOW_MS) continue;
    if (!sharesAgent(last, h)) continue;
    if (gapMs < bestGapMs) {
      bestGapMs = gapMs;
      bestIdx = i;
    }
  }
  return bestIdx;
}

function sharesAgent(a: HandoffEntry, b: HandoffEntry): boolean {
  return (
    a.source_agent_id === b.source_agent_id ||
    a.source_agent_id === b.target_agent_id ||
    a.target_agent_id === b.source_agent_id ||
    a.target_agent_id === b.target_agent_id
  );
}

function materialize(members: HandoffEntry[], now: Date): Workflow {
  const sorted = [...members].sort((a, b) =>
    a.observed_at < b.observed_at ? -1 : 1,
  );
  const root = sorted[0]!;
  const last = sorted[sorted.length - 1]!;
  const involved = new Set<string>();
  for (const h of sorted) {
    if (h.source_agent_id) involved.add(h.source_agent_id);
    if (h.target_agent_id) involved.add(h.target_agent_id);
  }
  return {
    workflow_id: workflowIdFromRoot(root.entry_id),
    root_handoff: root,
    member_handoffs: sorted,
    state: determineWorkflowState(sorted, now),
    started_at: root.observed_at,
    last_activity_at: last.observed_at,
    involved_agents: [...involved].sort(),
  };
}
