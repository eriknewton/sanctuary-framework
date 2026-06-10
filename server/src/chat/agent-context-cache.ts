/**
 * Sanctuary MCP Server, Operator Chat, Agent-Context Cache
 *
 * WP-V1.3-9 Tau-5 (criterion (e) of the v1.3 scope-lock revision; closes
 * WP-V1.3-9 Conversational Sovereignty Depth). Builds on Tau-1 (memory
 * persistence), Tau-2 (multi-turn coherence), Tau-3 (8-category dynamic
 * context routing), and Tau-4 (operator-query grammar). Tau-5 ships
 * proactive context awareness: the concierge knows which wrapped agents
 * the operator runs, their templates, current work, recent audit-log
 * activity, recent commitment chains, and recent Verascore deltas, and
 * folds that snapshot into every chat round-trip plus a starter
 * suggestion when a fresh thread opens.
 *
 * Architecture:
 *
 * - The cache is per-fortress: one `AgentContextCache` instance per
 *   `OperatorChatService` instance. The service-construction layer in
 *   `dashboard/v1_1/wiring.ts` wires the cache to the same agent
 *   registry + audit log it already passes to the Tau-3 fetchers, so
 *   data sources align across both surfaces.
 *
 * - Refresh is lazy: `refresh()` returns the latest snapshot list and
 *   updates the in-memory cache. `read()` is a synchronous accessor for
 *   the latest cached snapshot (returns `[]` until the first refresh
 *   resolves).
 *
 * - Cadence: callers schedule refreshes via `start()` (60-second timer)
 *   and trigger an explicit refresh on fortress-unlock by calling
 *   `refresh()` once at construction. Tests can opt out of the timer
 *   by leaving `start()` uncalled.
 *
 * Castle-walking discipline:
 *
 * - No new outbound surface. The cache reads server-local data only:
 *   the agent registry (in-memory) and the audit log (encrypted under
 *   L1 master key at rest). Optional Verascore receipt cache is read
 *   through a caller-provided source; absent, the verascore field
 *   degrades to null, never to an outbound HTTP call.
 *
 * - Encryption boundary held: the cache holds plain text already
 *   produced inside the fortress. Audit-log decryption happens inside
 *   the audit-log subsystem, not here.
 *
 * - Failure-mode handling is fail-soft: a refresh that throws (audit
 *   log read error, registry contention, oversize bundle) leaves the
 *   prior snapshot list intact and returns `[]` from the failed
 *   refresh. The caller can emit an audit event; the concierge
 *   degrades gracefully to no agent-state section. The user-facing
 *   query is never broken by a cache-refresh failure.
 *
 * Privacy invariant:
 *
 * Snapshots carry agent_id, harness, template, and aggregate counts.
 * They MUST NOT carry raw audit-log slices, raw operator queries, or
 * raw secret material. Counts are integers; current_work_summary is a
 * stable enum-derived string ("performed policy_change", "wrote to
 * state"); state_flags is a closed enum. The "Current agent state"
 * section the concierge renders into the substrate prompt aggregates
 * those fields only.
 *
 * Out of scope here (v1.4+ and later):
 *
 * - Cross-fortress agent state aggregation (v1.4 cross-tenant scope).
 * - Concierge-driven action execution (operator: "fix Cursor's
 *   session"). Defer to v1.5+ pending approval-flow trust model.
 * - Advanced ML-backed state inference (per-operator agent-state norms).
 *   Defer to v1.5+; out of scope for v1.3.
 */

import type { AuditLog } from "../l2-operational/audit-log.js";
import type { HubAgentRegistrySource } from "../hub/types.js";
import type { LocalAgentRecord } from "../contracts/v1.1/local-agent-records.js";

// ── Public types ─────────────────────────────────────────────────────────

/**
 * Stable enum of agent state flags surfaced into the substrate prompt
 * and the proactive-suggestion trigger. The order in `STATE_FLAG_ORDER`
 * encodes urgency: flags earlier in the list rank higher when the
 * prompt-section pruner has to drop low-urgency agents to fit budget.
 */
export type AgentStateFlag =
  | "stuck"
  | "has_pending_approvals"
  | "has_open_findings"
  | "active"
  | "idle";

const STATE_FLAG_ORDER: readonly AgentStateFlag[] = [
  "stuck",
  "has_pending_approvals",
  "has_open_findings",
  "active",
  "idle",
] as const;

/**
 * One snapshot entry per wrapped agent. Stable shape so the prompt
 * formatter and the proactive-suggestion generator can read off the
 * same data without re-fetching from the registry.
 *
 * Counts (`recent_audit_count_24h`, `recent_egress_count_24h`,
 * `recent_concordia_receipts_count_24h`) are integers derived from the
 * last-24h slice of the audit log. `recent_verascore_delta_24h` is
 * `null` when the optional Verascore source is not wired or returned
 * no delta.
 */
export interface AgentContextSnapshot {
  agent_id: string;
  agent_name: string;
  template: string;
  last_activity_at: string | null;
  current_work_summary: string | null;
  recent_audit_count_24h: number;
  recent_egress_count_24h: number;
  recent_concordia_receipts_count_24h: number;
  recent_verascore_delta_24h: number | null;
  state_flags: AgentStateFlag[];
}

/**
 * Optional source for the Verascore reputation delta surface. v1.0
 * Sanctuary does not currently expose a queryable Verascore receipt
 * cache server-side; the source is wired in on Verascore-bridge-aware
 * deployments and absent everywhere else. When absent, the snapshot's
 * `recent_verascore_delta_24h` field is null. The concierge functions
 * fully without it (non-dependency invariant).
 */
export interface VerascoreDeltaSource {
  /**
   * Return the most-recent 24h reputation delta for this agent, or
   * null when no delta is available. Implementations MUST be fast
   * (server-local, no outbound) so the cache refresh stays bounded.
   */
  read(agentId: string): number | null;
}

/**
 * One handler registration's removal callback.
 */
export type AgentContextChangeUnsubscribe = () => void;

export interface AgentContextCacheDeps {
  /** Operator identity that owns the agents this cache aggregates over. */
  identityId: string;
  /** Source of agent records, scoped to this operator's identity. */
  agentRegistry: HubAgentRegistrySource;
  /** Audit log used to derive recent-activity counts and state flags. */
  auditLog: AuditLog;
  /** Optional Verascore delta source. When absent, deltas degrade to null. */
  verascoreSource?: VerascoreDeltaSource;
  /** Hook invoked when a refresh throws. Defaults to a no-op. */
  onRefreshError?: (error: unknown) => void;
  /** Deterministic clock for tests. Defaults to `Date.now`. */
  clock?: () => number;
  /** Refresh cadence in ms. Defaults to 60_000. */
  refreshCadenceMs?: number;
  /**
   * Window in ms used to derive 24h counts. Defaults to 24h. Tunable
   * for tests so they can simulate older entries falling out of the
   * window without manipulating the clock.
   */
  windowMs?: number;
}

const DEFAULT_REFRESH_CADENCE_MS = 60 * 1000;
const DEFAULT_WINDOW_MS = 24 * 60 * 60 * 1000;
const STUCK_AGE_MS = 12 * 60 * 60 * 1000;
const IDLE_AGE_MS = 60 * 60 * 1000;
const COMPOSITION_PREFIX = "composition_";
const APPROVAL_OPS_REGEX = /(approval_request|cross_harness_approval)/i;
const EGRESS_OPS_REGEX = /(egress|outbound|outgoing|context_gate_)/i;
const SENTINEL_FINDING_OPS_REGEX = /(sentinel|finding|anomaly)/i;

/**
 * Per-fortress in-memory cache of agent context snapshots. See
 * file-level docstring for the invariants this class upholds.
 */
export class AgentContextCache {
  private readonly identityId: string;
  private readonly agentRegistry: HubAgentRegistrySource;
  private readonly auditLog: AuditLog;
  private readonly verascoreSource: VerascoreDeltaSource | undefined;
  private readonly onRefreshError: (error: unknown) => void;
  private readonly clock: () => number;
  private readonly cadenceMs: number;
  private readonly windowMs: number;

  private snapshots: AgentContextSnapshot[] = [];
  private observers = new Set<(snapshots: AgentContextSnapshot[]) => void>();
  private timer: ReturnType<typeof setInterval> | null = null;
  private inFlight = false;

  constructor(deps: AgentContextCacheDeps) {
    this.identityId = deps.identityId;
    this.agentRegistry = deps.agentRegistry;
    this.auditLog = deps.auditLog;
    this.verascoreSource = deps.verascoreSource;
    this.onRefreshError = deps.onRefreshError ?? (() => {});
    this.clock = deps.clock ?? (() => Date.now());
    this.cadenceMs =
      deps.refreshCadenceMs !== undefined && deps.refreshCadenceMs > 0
        ? deps.refreshCadenceMs
        : DEFAULT_REFRESH_CADENCE_MS;
    this.windowMs =
      deps.windowMs !== undefined && deps.windowMs > 0
        ? deps.windowMs
        : DEFAULT_WINDOW_MS;
  }

  /**
   * Run the refresh cycle. Returns the new snapshot list (which is
   * also stored as the cache state). On error, the prior snapshots
   * are kept and the resolved promise carries `[]`. The error is
   * dispatched to the `onRefreshError` hook so the caller can audit-
   * emit a degradation event.
   */
  async refresh(): Promise<AgentContextSnapshot[]> {
    if (this.inFlight) {
      // Coalesce concurrent refreshes; just return the latest state.
      // The in-flight refresh will update the cache when it settles.
      return this.snapshots.slice();
    }
    this.inFlight = true;
    try {
      const records = this.agentRegistry.list({ identity_id: this.identityId });
      const nowMs = this.clock();
      const sinceIso = new Date(nowMs - this.windowMs).toISOString();

      // Pull a generous slice of recent audit log entries scoped to
      // this operator. The query API filters by since + identity is
      // applied client-side because some audit producers emit with a
      // synthetic identity (e.g., system events).
      const recent = await this.auditLog.query({
        since: sinceIso,
        limit: 500,
      });
      const ownedRecent = recent.entries.filter(
        (e) => e.identity_id === this.identityId,
      );

      const next: AgentContextSnapshot[] = records.map((record) =>
        buildSnapshot({
          record,
          recentEntries: ownedRecent,
          nowMs,
          verascoreSource: this.verascoreSource,
        }),
      );

      this.snapshots = next;
      this.notifyObservers(next);
      return next.slice();
    } catch (err) {
      this.onRefreshError(err);
      return [];
    } finally {
      this.inFlight = false;
    }
  }

  /**
   * Synchronous read of the latest cached snapshot list. Returns `[]`
   * until the first `refresh()` resolves, or after a failure that left
   * the cache empty.
   */
  read(): AgentContextSnapshot[] {
    return this.snapshots.slice();
  }

  /**
   * Subscribe to refresh notifications. The handler fires once per
   * successful refresh with the new snapshot list. Returns an
   * unsubscribe callback the caller invokes on teardown.
   */
  observeChanges(
    handler: (snapshots: AgentContextSnapshot[]) => void,
  ): AgentContextChangeUnsubscribe {
    this.observers.add(handler);
    return () => {
      this.observers.delete(handler);
    };
  }

  /**
   * Start the periodic refresh timer. Idempotent. Tests typically do
   * not call this and trigger refreshes manually.
   */
  start(): void {
    if (this.timer !== null) return;
    this.timer = setInterval(() => {
      void this.refresh().catch(() => {
        // Errors already routed through onRefreshError inside refresh().
      });
    }, this.cadenceMs);
    if (typeof (this.timer as { unref?: () => void }).unref === "function") {
      (this.timer as { unref: () => void }).unref();
    }
  }

  /**
   * Stop the periodic refresh timer. Idempotent.
   */
  stop(): void {
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  private notifyObservers(snapshots: AgentContextSnapshot[]): void {
    for (const fn of this.observers) {
      try {
        fn(snapshots.slice());
      } catch {
        // Observer failure is non-fatal; the cache must keep refreshing.
      }
    }
  }
}

// ── Snapshot derivation ──────────────────────────────────────────────────

interface BuildSnapshotInputs {
  record: LocalAgentRecord;
  recentEntries: ReadonlyArray<{
    timestamp: string;
    operation: string;
    result: "success" | "failure";
    details?: Record<string, unknown>;
  }>;
  nowMs: number;
  verascoreSource: VerascoreDeltaSource | undefined;
}

/**
 * Derive one `AgentContextSnapshot` from a registry record + the
 * operator's recent audit slice. Pure modulo `verascoreSource.read()`;
 * unit-testable without standing up a live cache.
 */
export function buildSnapshot(
  inputs: BuildSnapshotInputs,
): AgentContextSnapshot {
  const { record, recentEntries, nowMs, verascoreSource } = inputs;
  const ownedByAgent = recentEntries.filter((e) => {
    const agentId =
      e.details && typeof e.details["agent_id"] === "string"
        ? (e.details["agent_id"] as string)
        : null;
    return agentId === record.agent_id;
  });

  const auditCount = ownedByAgent.length;
  const egressCount = ownedByAgent.filter((e) =>
    EGRESS_OPS_REGEX.test(e.operation),
  ).length;
  const compositionCount = ownedByAgent.filter((e) =>
    e.operation.startsWith(COMPOSITION_PREFIX),
  ).length;

  const lastActivityAtIso = record.last_activity_at;
  const lastActivityMs = lastActivityAtIso
    ? Date.parse(lastActivityAtIso)
    : Number.NaN;
  const lastActivityAge = Number.isFinite(lastActivityMs)
    ? nowMs - lastActivityMs
    : Number.POSITIVE_INFINITY;

  const lastEntry = ownedByAgent[ownedByAgent.length - 1];
  const lastWasFailure = lastEntry !== undefined && lastEntry.result === "failure";

  const stateFlags = new Set<AgentStateFlag>();
  // Stuck: no activity for 12h+ AND last event was a failure, OR the
  // record's own status indicates a harness/error condition.
  const recordStatusError =
    record.status_reason_class === "harness_error" ||
    record.status_reason_class === "harness_unreachable" ||
    record.status === "error";
  if (
    (lastActivityAge >= STUCK_AGE_MS && lastWasFailure) ||
    recordStatusError
  ) {
    stateFlags.add("stuck");
  }
  if (
    ownedByAgent.some((e) => APPROVAL_OPS_REGEX.test(e.operation))
  ) {
    stateFlags.add("has_pending_approvals");
  }
  if (
    ownedByAgent.some((e) => SENTINEL_FINDING_OPS_REGEX.test(e.operation))
  ) {
    stateFlags.add("has_open_findings");
  }
  // Active vs idle is decided last so it cannot mask a stuck/approval
  // signal: an agent with pending approvals is "has_pending_approvals
  // + (active|idle)" rather than just "active".
  if (lastActivityAge < IDLE_AGE_MS) {
    stateFlags.add("active");
  } else if (
    !stateFlags.has("stuck") &&
    !stateFlags.has("has_pending_approvals") &&
    !stateFlags.has("has_open_findings")
  ) {
    stateFlags.add("idle");
  }

  const orderedFlags = STATE_FLAG_ORDER.filter((f) => stateFlags.has(f));

  const verascore =
    verascoreSource !== undefined
      ? verascoreSource.read(record.agent_id)
      : null;

  return {
    agent_id: record.agent_id,
    agent_name: record.agent_id,
    template:
      typeof record.channel_template_id === "string"
        ? record.channel_template_id
        : "no_template",
    last_activity_at: lastActivityAtIso ?? null,
    current_work_summary: deriveCurrentWorkSummary(lastEntry),
    recent_audit_count_24h: auditCount,
    recent_egress_count_24h: egressCount,
    recent_concordia_receipts_count_24h: compositionCount,
    recent_verascore_delta_24h: verascore,
    state_flags: orderedFlags,
  };
}

function deriveCurrentWorkSummary(
  lastEntry:
    | {
        timestamp: string;
        operation: string;
        result: "success" | "failure";
      }
    | undefined,
): string | null {
  if (!lastEntry) return null;
  const verb = lastEntry.result === "failure" ? "failed" : "performed";
  return `${verb} ${lastEntry.operation}`;
}

// ── Prompt rendering ─────────────────────────────────────────────────────

const SECTION_HEADER = "## Current agent state";

/**
 * Approximate-token estimator. Matches the chars/4 proxy used across
 * the substrate prompt budget surfaces (Tau-2 priorTurns budget,
 * Tau-3 dynamic-context budget).
 */
function approxTokenLen(text: string): number {
  return Math.ceil(text.length / 4);
}

/**
 * Default cap on the rendered "Current agent state" section, in tokens.
 * Sized so the section sits comfortably alongside the static reference
 * + dynamic-context fold + prior-turns fold within the substrate's
 * nominal concierge prompt budget.
 */
export const DEFAULT_AGENT_CONTEXT_TOKEN_BUDGET = 400;

/**
 * Format one snapshot as a one-line bullet for the prompt. Format is
 * stable plain text so small local models parse it cleanly:
 *
 *   `- <agent_name> (template: <template>): <flags>, <counts>, <verascore>`
 */
function formatSnapshotLine(snapshot: AgentContextSnapshot): string {
  const flagLabel = snapshot.state_flags.join("+") || "no_flags";
  const work = snapshot.current_work_summary
    ? `, last: ${snapshot.current_work_summary}`
    : "";
  const verascore =
    snapshot.recent_verascore_delta_24h !== null
      ? `, verascore Δ${snapshot.recent_verascore_delta_24h.toFixed(2)}`
      : "";
  return `- ${snapshot.agent_name} (template: ${snapshot.template}): ${flagLabel}, ${snapshot.recent_audit_count_24h} audit/24h, ${snapshot.recent_concordia_receipts_count_24h} receipts${verascore}${work}`;
}

/**
 * Sort key for urgency-ordered prune. Lower number = higher urgency.
 * Returns the index of the highest-urgency flag this snapshot carries
 * (using `STATE_FLAG_ORDER` as the canonical ordering); used as a
 * tiebreaker so "stuck" agents are kept first when budget pressure
 * forces drops.
 */
function urgencyRank(snapshot: AgentContextSnapshot): number {
  for (let i = 0; i < STATE_FLAG_ORDER.length; i++) {
    if (snapshot.state_flags.includes(STATE_FLAG_ORDER[i] as AgentStateFlag)) {
      return i;
    }
  }
  return STATE_FLAG_ORDER.length;
}

/**
 * Render the "Current agent state" section. Returns the empty string
 * when no snapshots are available so the caller can stitch
 * conditionally without shipping a header above an empty body.
 *
 * Token-budget enforcement is urgency-ordered: snapshots are sorted by
 * urgency rank ascending (stuck > pending-approvals > findings >
 * active > idle), then lines are added until the next would exceed
 * the budget. The kept-list is rendered in the same urgency-ordered
 * sequence so the highest-priority agents land at the top of the
 * section even when budget pressure drops the tail.
 */
export function formatCurrentAgentStateSection(
  snapshots: ReadonlyArray<AgentContextSnapshot>,
  opts?: { maxTokens?: number },
): string {
  if (snapshots.length === 0) return "";
  const budget = opts?.maxTokens ?? DEFAULT_AGENT_CONTEXT_TOKEN_BUDGET;
  const sorted = [...snapshots].sort(
    (a, b) => urgencyRank(a) - urgencyRank(b),
  );

  const headerTokens = approxTokenLen(`${SECTION_HEADER}\n`);
  const sepTokens = approxTokenLen("\n");
  let runningTokens = headerTokens;
  const kept: string[] = [];
  for (const snap of sorted) {
    const line = formatSnapshotLine(snap);
    const tokens = approxTokenLen(line) + (kept.length > 0 ? sepTokens : 0);
    if (kept.length === 0) {
      kept.push(line);
      runningTokens += tokens;
      continue;
    }
    if (runningTokens + tokens > budget) break;
    kept.push(line);
    runningTokens += tokens;
  }
  return `${SECTION_HEADER}\n${kept.join("\n")}`;
}

// ── Proactive starter generation ─────────────────────────────────────────

/**
 * Stable enum of the trigger classes the starter generator surfaces.
 * Carried into the audit emission so dashboards can group by cause.
 */
export type ProactiveStarterTrigger =
  | "stuck_agent"
  | "pending_approvals"
  | "open_findings"
  | "all_idle";

export interface ConciergeProactiveStarter {
  text: string;
  trigger: ProactiveStarterTrigger;
  /**
   * How many agents contributed to this trigger. For `stuck_agent` and
   * `open_findings` this is the count of agents in that state; for
   * `pending_approvals` it is the count of agents with pending; for
   * `all_idle` it is the total agent count.
   */
  triggered_agents_count: number;
}

/**
 * Decide whether to surface a proactive starter, and if so what it
 * says. Returns null when no starter should fire (empty fortress, or
 * no signal-bearing state) so the dashboard can render a blank input
 * cleanly.
 *
 * Ordering (highest urgency first, matches `STATE_FLAG_ORDER`):
 *
 * 1. `stuck_agent`: at least one snapshot has the `stuck` flag.
 * 2. `pending_approvals`: at least one snapshot has
 *    `has_pending_approvals`.
 * 3. `open_findings`: at least one snapshot has `has_open_findings`.
 * 4. `all_idle`: every non-empty snapshot list with no urgency flags
 *    surfaces a "your fortress is quiet" starter.
 */
export function generateProactiveStarter(
  snapshots: ReadonlyArray<AgentContextSnapshot>,
): ConciergeProactiveStarter | null {
  if (snapshots.length === 0) return null;

  const stuck = snapshots.filter((s) => s.state_flags.includes("stuck"));
  if (stuck.length > 0) {
    const first = stuck[0];
    if (first === undefined) return null;
    const last = first.current_work_summary
      ? ` (last: ${first.current_work_summary})`
      : "";
    return {
      text: `Your ${first.agent_name} agent looks stuck${last}. Should I check its session state?`,
      trigger: "stuck_agent",
      triggered_agents_count: stuck.length,
    };
  }

  const pending = snapshots.filter((s) =>
    s.state_flags.includes("has_pending_approvals"),
  );
  if (pending.length > 0) {
    const names = pending.slice(0, 3).map((s) => s.agent_name).join(", ");
    return {
      text: `You have pending approvals across ${names}. Want to walk through them?`,
      trigger: "pending_approvals",
      triggered_agents_count: pending.length,
    };
  }

  const findings = snapshots.filter((s) =>
    s.state_flags.includes("has_open_findings"),
  );
  if (findings.length > 0) {
    return {
      text: `Sentinel has open findings on ${findings.length} ${findings.length === 1 ? "agent" : "agents"}. Want a summary?`,
      trigger: "open_findings",
      triggered_agents_count: findings.length,
    };
  }

  // No urgency flags but agents exist: idle starter.
  return {
    text: "Your fortress is quiet. Anything you'd like to inspect?",
    trigger: "all_idle",
    triggered_agents_count: snapshots.length,
  };
}
