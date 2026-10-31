/**
 * Per-instance posture producers with bounded admission and response waits.
 * An in-process timer cannot preempt synchronous event-loop work. Elapsed-time
 * checks classify a synchronous overrun honestly once control returns.
 * Reuse bounds concurrent readers, not per-request caching on the production route, whose harness scan advances the audit sequence.
 */
import { failedExclusiveEgressStatus } from "./posture.js";
import type { CastleWallPosture, AuditDigest, UnwrappedRoster, CustodyExitPanel, PostureAgentRow } from "./posture.js";
import type { FeatureHealthPanel } from "./feature-health.js";
import type { QueryPrivacySection } from "./posture-query-privacy.js";
// Field types come from the shapers so the store does not depend back on its wire container.
interface CappablePosturePanels {
  castle_wall: CastleWallPosture;
  digest: AuditDigest;
  unwrapped: UnwrappedRoster;
  feature_health: FeatureHealthPanel;
  custody_exit: CustodyExitPanel;
  query_privacy: QueryPrivacySection;
  federation: { available: boolean; enabled: boolean; fleet_node_count: number };
  agents: PostureAgentRow[];
}

export const POSTURE_PANEL_IDS = [
  "producer_keys", "agents_roster", "exclusive_egress", "protection_subject",
  "enforcement_availability", "vault_provision_claim", "castle_wall", "digest",
  "unwrapped", "feature_health", "custody_exit", "federation", "query_privacy",
] as const;
/** State of a local pinned-key observation, not a claim of enforcement. */
export type ProducerKeyObservation = "unknown" | "present" | "absent" | "unreadable";
export type PosturePanelId = typeof POSTURE_PANEL_IDS[number];
// Must match the reason copy in dashboard/v1_1/client.ts, posture-home-html.ts, and posture-agent-html.ts.
export type PosturePanelReason = "budget_exceeded" | "producer_failed" | "never_completed" | "upstream_unavailable" | "observation_superseded";
export interface PosturePanelStatus {
  state: "fresh" | "stale" | "unavailable";
  completed_at: string | null;
  age_ms: number | null;
  budget_ms: number;
  reason: PosturePanelReason | null;
}
// Each stage reserves its own share of the four-second response deadline.
export const POSTURE_PRELUDE_BUDGET_MS = 400;
export const POSTURE_SHARED_RESOLVER_BUDGET_MS = 600;
export const POSTURE_PANEL_BUDGET_MS = 1_600;
export const POSTURE_QUERY_PRIVACY_BUDGET_MS = 400;
export const POSTURE_HOME_COMPOSE_BUDGET_MS = POSTURE_PRELUDE_BUDGET_MS + POSTURE_SHARED_RESOLVER_BUDGET_MS + POSTURE_PANEL_BUDGET_MS + POSTURE_QUERY_PRIVACY_BUDGET_MS;
// Must match the imported deadline relation in posture-panel-producer.test.ts;
// compose plus this serialization/flush reserve must fit DASHBOARD_READ_RESPONSE_DEADLINE_MS.
export const POSTURE_HOME_RESPONSE_HEADROOM_MS = 500;
// Must match AUDIT_EAGER_SENTINEL_INTERVAL_MS in operational/audit-log.ts.
export const POSTURE_PANEL_REUSE_MS = 2_000;
export const POSTURE_PANEL_SINGLE_FLIGHT_CAP = 1;
export const POSTURE_PRODUCER_KEYS_BUDGET_MS = POSTURE_PRELUDE_BUDGET_MS;
export const POSTURE_AGENTS_ROSTER_BUDGET_MS = POSTURE_SHARED_RESOLVER_BUDGET_MS;
export const POSTURE_EXCLUSIVE_EGRESS_BUDGET_MS = POSTURE_SHARED_RESOLVER_BUDGET_MS;
export const POSTURE_PROTECTION_SUBJECT_BUDGET_MS = POSTURE_SHARED_RESOLVER_BUDGET_MS;
export const POSTURE_ENFORCEMENT_AVAILABILITY_BUDGET_MS = POSTURE_SHARED_RESOLVER_BUDGET_MS;
export const POSTURE_VAULT_PROVISION_CLAIM_BUDGET_MS = POSTURE_SHARED_RESOLVER_BUDGET_MS;
export const POSTURE_CASTLE_WALL_BUDGET_MS = POSTURE_PANEL_BUDGET_MS;
export const POSTURE_DIGEST_BUDGET_MS = POSTURE_PANEL_BUDGET_MS;
export const POSTURE_UNWRAPPED_BUDGET_MS = POSTURE_PANEL_BUDGET_MS;
export const POSTURE_FEATURE_HEALTH_BUDGET_MS = POSTURE_PANEL_BUDGET_MS;
export const POSTURE_CUSTODY_EXIT_BUDGET_MS = POSTURE_PANEL_BUDGET_MS;
export const POSTURE_FEDERATION_BUDGET_MS = POSTURE_PANEL_BUDGET_MS;
export const POSTURE_PANEL_BUDGETS: Record<PosturePanelId, number> = {
  producer_keys: POSTURE_PRODUCER_KEYS_BUDGET_MS, agents_roster: POSTURE_AGENTS_ROSTER_BUDGET_MS,
  exclusive_egress: POSTURE_EXCLUSIVE_EGRESS_BUDGET_MS, protection_subject: POSTURE_PROTECTION_SUBJECT_BUDGET_MS,
  enforcement_availability: POSTURE_ENFORCEMENT_AVAILABILITY_BUDGET_MS, vault_provision_claim: POSTURE_VAULT_PROVISION_CLAIM_BUDGET_MS,
  castle_wall: POSTURE_CASTLE_WALL_BUDGET_MS, digest: POSTURE_DIGEST_BUDGET_MS,
  unwrapped: POSTURE_UNWRAPPED_BUDGET_MS, feature_health: POSTURE_FEATURE_HEALTH_BUDGET_MS,
  custody_exit: POSTURE_CUSTODY_EXIT_BUDGET_MS, federation: POSTURE_FEDERATION_BUDGET_MS,
  query_privacy: POSTURE_QUERY_PRIVACY_BUDGET_MS,
};
export interface PanelSnapshot<T> { value: T | undefined; status: PosturePanelStatus }
/** Explicit input-free key for producers whose only freshness input is the audit sequence. */
export const NO_PANEL_INPUTS = "no_panel_inputs";
interface Completed { value: unknown; at: number; sequence: number; generation: number; inputKey: string }
interface Slot {
  state: "state_IDLE" | "state_RUNNING" | "state_SETTLED";
  generation: number;
  last?: Completed;
  flight?: { waiters: Set<(reason: PosturePanelReason | null) => void> };
}
export interface PosturePanelStore {
  /** Read within the panel budget, matching the resolver snapshot key supplied by posture-routes.ts. */
  read<T>(id: PosturePanelId, sequence: number, produce: () => T | Promise<T>, inputKey: string): Promise<PanelSnapshot<T>>;
  /** Test seam: count active response waits; expired waits retain no flight reaction. Not exported by the module barrel. */
  waiterCount(id: PosturePanelId): number;
  /** Discard a completed observation before rechecking transient evidence; live admission stays held. */
  invalidate(id: PosturePanelId): void;
  snapshot<T>(id: PosturePanelId, reason?: PosturePanelReason): PanelSnapshot<T>;
  ids(): readonly PosturePanelId[];
}
/** Create one store per composition root; no producer state is shared between servers. */
export function createPosturePanelStore(options: {
  now?: () => number;
  setTimer?: typeof setTimeout;
  clearTimer?: typeof clearTimeout;
} = {}): PosturePanelStore {
  const now = options.now ?? Date.now;
  const setTimer = options.setTimer ?? setTimeout;
  const clearTimer = options.clearTimer ?? clearTimeout;
  // Closed ids each retain exactly one last-complete result and at most one run;
  // no caller-controlled key or repeated timeout can grow this store.
  const slots = new Map<PosturePanelId, Slot>(POSTURE_PANEL_IDS.map(id => [id, { state: "state_IDLE", generation: 0 }]));
  function snapshot<T>(id: PosturePanelId, reason: PosturePanelReason | null = "never_completed"): PanelSnapshot<T> {
    const last = slots.get(id)!.last;
    return { value: last?.value as T | undefined, status: {
      state: reason === null ? "fresh" : last ? "stale" : "unavailable",
      completed_at: last ? new Date(last.at).toISOString() : null,
      age_ms: last ? Math.max(0, now() - last.at) : null,
      budget_ms: POSTURE_PANEL_BUDGETS[id], reason,
    } };
  }
  return {
    snapshot,
    invalidate: id => { slots.get(id)!.last = undefined; },
    ids: () => [...slots.keys()],
    waiterCount: id => slots.get(id)!.flight?.waiters.size ?? 0,
    async read<T>(id: PosturePanelId, sequence: number, produce: () => T | Promise<T>, inputKey: string): Promise<PanelSnapshot<T>> {
      const slot = slots.get(id)!;
      const budget = POSTURE_PANEL_BUDGETS[id];
      const started = now();
      // inputKey must match producerKeysInputKey or evidenceInputKey in posture-routes.ts for dependent reads.
      // Reuse is keyed on audit state so a local append is visible next request;
      // age alone never stands in for freshness. Other-process appends remain
      // visible at the eager byte-pass cadence because they do not advance this counter.
      if (slot.last && slot.last.sequence === sequence && slot.last.inputKey === inputKey && started - slot.last.at < POSTURE_PANEL_REUSE_MS) {
        return snapshot<T>(id, null);
      }
      if (!slot.flight) {
        slot.state = "state_RUNNING";
        const generation = ++slot.generation;
        const flight = { waiters: new Set<(reason: PosturePanelReason | null) => void>() };
        slot.flight = flight;
        let settledReason: PosturePanelReason | null = "producer_failed";
        // One reaction chain owns settlement; timed-out readers retain no reaction on the run.
        // Deferral contains a synchronous throw in this producer's failure path.
        void Promise.resolve().then(produce).then(value => {
          // A generation mismatch invalidates only this panel, never the whole home.
          if (slot.generation !== generation) return;
          slot.last = { value, at: now(), sequence, generation, inputKey };
          settledReason = null;
        }).catch(() => { settledReason = "producer_failed"; }).finally(() => {
          // Admission belongs to the underlying run until settlement, including late completion.
          slot.state = "state_SETTLED";
          slot.flight = undefined;
          for (const resolve of flight.waiters) resolve(settledReason);
          flight.waiters.clear();
        });
      }
      const flight = slot.flight;
      let timer: ReturnType<typeof setTimeout> | undefined;
      let waiter!: (reason: PosturePanelReason | null) => void;
      // Each wait is bounded independently; timeout removes its waiter but never releases admission.
      const reason = await new Promise<PosturePanelReason | null>(resolve => {
        waiter = resolve;
        flight.waiters.add(waiter);
        timer = setTimer(() => {
          flight.waiters.delete(waiter);
          resolve("budget_exceeded");
        }, budget);
      });
      if (timer !== undefined) clearTimer(timer);
      // Timers cannot preempt synchronous work, so elapsed time also gates freshness.
      const boundedReason = now() - started >= budget ? "budget_exceeded" : reason;
      const result = snapshot<T>(id, boundedReason);
      // A joined run proves only its admission snapshot, including resolver values, not a newer request's inputs.
      if (boundedReason === null && (slot.last?.sequence !== sequence || slot.last?.inputKey !== inputKey)) {
        result.status.state = "stale";
        result.status.reason = "observation_superseded";
      }
      return result;
    },
  };
}
/** Lower historical evidence to existing non-green states without mutating cached values. */
export function capStalePanel<K extends keyof CappablePosturePanels>(id: K, value: CappablePosturePanels[K]): CappablePosturePanels[K] {
  // A complete historical value is useful context but cannot carry current green claims.
  if (id === "castle_wall") {
    const wall = value as CappablePosturePanels["castle_wall"];
    return { ...wall, arm_state: wall.arm_state === "armed" ? "unknown" : wall.arm_state,
      evidence_basis: "stale_evidence", audit_integrity_ok: false, producer_authenticity: "not_applicable",
      ...(wall.exclusive_egress ? { exclusive_egress: failedExclusiveEgressStatus("budget_exceeded") } : {}),
      ...(wall.enforcement_availability ? { enforcement_availability: { ...wall.enforcement_availability, status: "undetermined", reason: "availability_budget_exceeded" } } : {}),
      ...(wall.castle_wall_provision ? { castle_wall_provision: "not_yet_walled" } : {}),
    } as unknown as CappablePosturePanels[K];
  }
  if (id === "feature_health") {
    const panel = value as CappablePosturePanels["feature_health"];
    return { ...panel, audit_integrity_ok: false, rows: panel.rows.map(row => ({ ...row,
      status: row.status === "active" ? "unknown" : row.status, basis: "stale_evidence", audit_integrity_ok: false,
    ...(row.enforcement_availability ? { enforcement_availability: { ...row.enforcement_availability, status: "undetermined", reason: "availability_budget_exceeded" } } : {}),
    })), plugin_rows: panel.plugin_rows.map(row => ({ ...row, status: row.status === "active" ? "unknown" : row.status, basis: "integrity_tainted" })) } as unknown as CappablePosturePanels[K];
  }
  // The cap withholds the verdict's authority, it never changes what was observed.
  if (id === "digest") return { ...(value as CappablePosturePanels["digest"]), chain_verified: false,
    window_complete: false, window_incomplete_reason: "coverage_unknown" } as unknown as CappablePosturePanels[K];
  if (id === "query_privacy") {
    const panel = value as CappablePosturePanels["query_privacy"];
    return { ...panel, tier_a_strip_observed: false, rows: panel.rows.map(row => ({ ...row,
      status: row.status === "active" ? "unknown" : row.status,
      ...(row.tier === "A" ? { tier_a_evidence: "no_calls" } : {}),
    })) } as unknown as CappablePosturePanels[K];
  }
  if (id === "custody_exit") return { ...(value as CappablePosturePanels["custody_exit"]), audit_integrity_ok: false, clean_exit_guaranteed: false } as unknown as CappablePosturePanels[K];
  if (id === "federation") return { ...(value as CappablePosturePanels["federation"]), available: false } as unknown as CappablePosturePanels[K];
  if (id === "agents") return (value as CappablePosturePanels["agents"]).map(row => ({ ...row, enforcement_active: "unknown" })) as CappablePosturePanels[K];
  return value;
}
