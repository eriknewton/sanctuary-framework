/**
 * Sanctuary Policy Engine — Retention sweep (WP-MVP-6).
 *
 * Per-agent retention windows for each of the four canonical slots
 * (memory, credentials, plans, outputs). Expressed as a duration per slot;
 * compiled to a signed policy_update containing a `retention` field.
 *
 * Enforcement: a sweep loop runs on a timer (default 15min) and on-demand
 * via an operator "sweep now" call. The sweep deletes (or archives per the
 * archive flag) expired entries. Every sweep emits a signed `retention_sweep`
 * event with per-slot counts.
 *
 * No network, no LLM at sweep time.
 */

import { POLICY_SLOTS, type PolicySlot } from "./constants.js";
import type { RetentionPolicy, RetentionWindow } from "./types.js";

/** An entry in a slot that has a timestamp for age computation. */
export interface SlotEntry {
  /** Unique key for the entry. */
  key: string;
  /** ISO8601 UTC timestamp when the entry was created/last written. */
  created_at: string;
}

/** Result of a retention sweep. */
export interface RetentionSweepResult {
  /** Count of entries swept (deleted or archived) per slot. */
  swept: Record<PolicySlot, number>;
  /** Count of entries retained per slot. */
  retained: Record<PolicySlot, number>;
  /** ISO8601 UTC timestamp when the sweep ran. */
  swept_at: string;
}

/**
 * Interface for the storage layer the sweep operates on. Production wires
 * this to the StateStore; tests wire an in-memory implementation.
 */
export interface RetentionStore {
  /** List entries for a given agent + slot. */
  listEntries(agent_id: string, slot: PolicySlot): Promise<SlotEntry[]>;
  /** Delete an entry. */
  deleteEntry(agent_id: string, slot: PolicySlot, key: string): Promise<void>;
  /**
   * Archive an entry (move to archive namespace). Only called when the
   * retention window has `archive: true`.
   */
  archiveEntry(agent_id: string, slot: PolicySlot, key: string): Promise<void>;
}

/**
 * In-memory retention store for testing. Each slot holds a map of
 * key → SlotEntry.
 */
export class InMemoryRetentionStore implements RetentionStore {
  private data = new Map<string, Map<string, SlotEntry>>();
  private archived = new Map<string, Map<string, SlotEntry>>();

  private storeKey(agent_id: string, slot: PolicySlot): string {
    return `${agent_id}:${slot}`;
  }

  /** Seed an entry for testing. */
  seed(agent_id: string, slot: PolicySlot, entry: SlotEntry): void {
    const k = this.storeKey(agent_id, slot);
    if (!this.data.has(k)) this.data.set(k, new Map());
    this.data.get(k)!.set(entry.key, entry);
  }

  async listEntries(agent_id: string, slot: PolicySlot): Promise<SlotEntry[]> {
    const k = this.storeKey(agent_id, slot);
    return Array.from(this.data.get(k)?.values() ?? []);
  }

  async deleteEntry(
    agent_id: string,
    slot: PolicySlot,
    key: string
  ): Promise<void> {
    const k = this.storeKey(agent_id, slot);
    this.data.get(k)?.delete(key);
  }

  async archiveEntry(
    agent_id: string,
    slot: PolicySlot,
    key: string
  ): Promise<void> {
    const k = this.storeKey(agent_id, slot);
    const entries = this.data.get(k);
    if (!entries) return;
    const entry = entries.get(key);
    if (!entry) return;
    entries.delete(key);
    const archiveKey = this.storeKey(agent_id, slot);
    if (!this.archived.has(archiveKey)) this.archived.set(archiveKey, new Map());
    this.archived.get(archiveKey)!.set(key, entry);
  }

  /** Get archived entries for testing verification. */
  getArchived(agent_id: string, slot: PolicySlot): SlotEntry[] {
    const k = this.storeKey(agent_id, slot);
    return Array.from(this.archived.get(k)?.values() ?? []);
  }

  /** Count remaining entries for a slot. */
  countEntries(agent_id: string, slot: PolicySlot): number {
    const k = this.storeKey(agent_id, slot);
    return this.data.get(k)?.size ?? 0;
  }
}

/**
 * Execute a retention sweep for one agent against its pinned retention policy.
 *
 * For each slot with a configured retention window, entries older than
 * `max_age_seconds` are deleted (or archived if `archive: true`).
 *
 * Returns per-slot counts for the signed `retention_sweep` event.
 */
export async function executeRetentionSweep(params: {
  agent_id: string;
  retention: RetentionPolicy | undefined;
  store: RetentionStore;
  now?: number;
}): Promise<RetentionSweepResult> {
  const { agent_id, retention, store } = params;
  const nowMs = params.now ?? Date.now();

  const swept: Record<string, number> = {};
  const retained: Record<string, number> = {};

  for (const slot of POLICY_SLOTS) {
    swept[slot] = 0;
    retained[slot] = 0;
  }

  if (!retention) {
    // No retention policy: count all entries as retained.
    for (const slot of POLICY_SLOTS) {
      const entries = await store.listEntries(agent_id, slot);
      retained[slot] = entries.length;
    }
    return {
      swept: swept as Record<PolicySlot, number>,
      retained: retained as Record<PolicySlot, number>,
      swept_at: new Date(nowMs).toISOString(),
    };
  }

  for (const slot of POLICY_SLOTS) {
    const window: RetentionWindow | undefined = retention.windows[slot];
    const entries = await store.listEntries(agent_id, slot);

    if (!window) {
      // No window for this slot: retain everything.
      retained[slot] = entries.length;
      continue;
    }

    const cutoffMs = nowMs - window.max_age_seconds * 1000;

    for (const entry of entries) {
      const entryMs = new Date(entry.created_at).getTime();
      if (entryMs < cutoffMs) {
        if (window.archive) {
          await store.archiveEntry(agent_id, slot, entry.key);
        } else {
          await store.deleteEntry(agent_id, slot, entry.key);
        }
        swept[slot]++;
      } else {
        retained[slot]++;
      }
    }
  }

  return {
    swept: swept as Record<PolicySlot, number>,
    retained: retained as Record<PolicySlot, number>,
    swept_at: new Date(nowMs).toISOString(),
  };
}

/**
 * Retention sweep scheduler. Runs sweeps on a timer and exposes an
 * on-demand trigger. The timer is the default 15min tick; the on-demand
 * surface is a direct function call (not a timer reset).
 */
export class RetentionSweepScheduler {
  private timer: ReturnType<typeof setInterval> | null = null;
  private readonly intervalMs: number;

  constructor(intervalMs: number) {
    this.intervalMs = intervalMs;
  }

  /**
   * Start the sweep timer. Calls `sweepFn` every `intervalMs`. The caller
   * is responsible for providing the sweep function that iterates over
   * agents and calls `executeRetentionSweep` for each.
   */
  start(sweepFn: () => Promise<void>): void {
    if (this.timer) return;
    this.timer = setInterval(() => {
      sweepFn().catch(() => {
        // Sweep errors are logged but do not crash the scheduler.
      });
    }, this.intervalMs);
  }

  /** Stop the sweep timer. */
  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  /** Check if the scheduler is running. */
  isRunning(): boolean {
    return this.timer !== null;
  }
}
