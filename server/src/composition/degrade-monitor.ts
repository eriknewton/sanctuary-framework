/**
 * Sanctuary Composition v1.0 -- Degrade Monitor
 *
 * Tracks sidecar health, surfaces degrade state to the attestation
 * service from WP-MVP-9, emits badge state change events.
 *
 * Sidecar crash is NEVER a fortress-halt condition. The monitor
 * ensures that composition degrades gracefully to badge-yellow
 * with a replay queue for recovery.
 */

import type { SidecarState } from "./sidecar-manager.js";
import type { CompositionDegradeState, CommitmentEvent } from "./types.js";

/**
 * Event emitted when composition degrade state changes.
 * Consumed by the attestation service to update badges.
 */
export interface DegradeStateChangeEvent {
  degraded: boolean;
  reason: string;
  sidecar_state: SidecarState;
  consecutive_crashes: number;
  replay_queue_depth: number;
  timestamp: string;
}

export type DegradeStateChangeListener = (event: DegradeStateChangeEvent) => void;

/**
 * Monitors composition health and manages the replay queue.
 */
export class DegradeMonitor {
  private degraded = false;
  private reason = "";
  private consecutiveCrashes = 0;
  private sidecarState: SidecarState = "stopped";
  private lastCrashAt: string | null = null;
  private lastSuccessAt: string | null = null;
  private replayQueue: CommitmentEvent[] = [];
  private maxQueueDepth: number;
  private listeners: DegradeStateChangeListener[] = [];

  constructor(maxQueueDepth: number) {
    this.maxQueueDepth = maxQueueDepth;
  }

  /**
   * Register a listener for degrade state changes.
   */
  onStateChange(listener: DegradeStateChangeListener): void {
    this.listeners.push(listener);
  }

  /**
   * Report a sidecar crash. Enters degraded mode.
   */
  reportCrash(crashes: number, lastCrashAt: string): void {
    this.consecutiveCrashes = crashes;
    this.lastCrashAt = lastCrashAt;
    this.degraded = true;
    this.reason = `Sidecar crashed (${crashes} consecutive)`;
    this.emitStateChange();
  }

  /**
   * Report sidecar state change.
   */
  reportSidecarState(state: SidecarState): void {
    this.sidecarState = state;

    if (state === "running") {
      this.degraded = false;
      this.reason = "";
      this.consecutiveCrashes = 0;
      this.emitStateChange();
    } else if (state === "crashed" || state === "restarting") {
      this.degraded = true;
      this.reason = state === "crashed" ? "Sidecar crashed" : "Sidecar restarting";
      this.emitStateChange();
    }
  }

  /**
   * Report a successful sidecar operation.
   */
  reportSuccess(): void {
    this.lastSuccessAt = new Date().toISOString();
    if (this.degraded && this.sidecarState === "running") {
      this.degraded = false;
      this.reason = "";
      this.consecutiveCrashes = 0;
      this.emitStateChange();
    }
  }

  /**
   * Queue a commitment event for replay when the sidecar recovers.
   * Returns false if the queue is full (event dropped).
   */
  queueForReplay(event: CommitmentEvent): boolean {
    if (this.replayQueue.length >= this.maxQueueDepth) {
      return false; // Queue full, event dropped
    }
    this.replayQueue.push(event);
    return true;
  }

  /**
   * Drain the replay queue (called when sidecar recovers).
   * Returns all queued events and clears the queue.
   */
  drainReplayQueue(): CommitmentEvent[] {
    const events = [...this.replayQueue];
    this.replayQueue = [];
    return events;
  }

  /**
   * Get the current degrade state snapshot.
   */
  getState(): CompositionDegradeState {
    return {
      degraded: this.degraded,
      reason: this.reason,
      consecutive_crashes: this.consecutiveCrashes,
      replay_queue_active: this.replayQueue.length > 0,
      replay_queue_depth: this.replayQueue.length,
      last_crash_at: this.lastCrashAt,
      last_success_at: this.lastSuccessAt,
      sidecar_state: this.sidecarState,
    };
  }

  /**
   * Check if composition is currently degraded.
   */
  isDegraded(): boolean {
    return this.degraded;
  }

  /**
   * Get the replay queue depth.
   */
  getReplayQueueDepth(): number {
    return this.replayQueue.length;
  }

  /**
   * Clear all state. Test-only.
   */
  clear(): void {
    this.degraded = false;
    this.reason = "";
    this.consecutiveCrashes = 0;
    this.sidecarState = "stopped";
    this.lastCrashAt = null;
    this.lastSuccessAt = null;
    this.replayQueue = [];
    this.listeners = [];
  }

  private emitStateChange(): void {
    const event: DegradeStateChangeEvent = {
      degraded: this.degraded,
      reason: this.reason,
      sidecar_state: this.sidecarState,
      consecutive_crashes: this.consecutiveCrashes,
      replay_queue_depth: this.replayQueue.length,
      timestamp: new Date().toISOString(),
    };
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch {
        // Listener errors must not propagate.
      }
    }
  }
}
