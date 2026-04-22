/**
 * Sanctuary Chat v1.0 — Presence System
 *
 * Four-state presence (active / idle / away / offline) per Q2 of the
 * architecture walkthrough. Staleness-driven transitions:
 *
 *   60s no heartbeat  -> idle
 *   5min no heartbeat -> away
 *   15min no heartbeat -> offline
 *
 * Presence is published as signed ephemeral events on a dedicated
 * libp2p gossipsub topic. NOT encrypted (low-sensitivity).
 * NOT audit-logged (ephemeral).
 */

import { SIGNATURE_SCHEME_V1 } from "../mesh/constants.js";
import type { SignedEvent } from "../mesh/types.js";
import {
  PRESENCE_HEARTBEAT_INTERVAL_MS,
  PRESENCE_STALENESS,
  type PresenceState,
} from "./constants.js";
import { packEphemeralEvent } from "./ephemeral-event.js";
import type { PeerPresence, PresencePayload } from "./types.js";

// ═══════════════════════════════════════════════════════════════════════
// Presence tracker (receiver side)
// ═══════════════════════════════════════════════════════════════════════

export interface PresenceChangeListener {
  (memberId: string, oldState: PresenceState, newState: PresenceState): void;
}

/**
 * Tracks presence for all peers in a fortress. Receives heartbeat events
 * and computes staleness-based state transitions.
 */
export class PresenceTracker {
  private peers = new Map<string, PeerPresence>();
  private listeners: PresenceChangeListener[] = [];
  private evalTimer: ReturnType<typeof setInterval> | null = null;

  /** Evaluation interval for staleness checks (default 10s). */
  private readonly evalIntervalMs: number;

  constructor(evalIntervalMs = 10_000) {
    this.evalIntervalMs = evalIntervalMs;
  }

  /** Register a listener for presence state changes. */
  onPresenceChange(listener: PresenceChangeListener): void {
    this.listeners.push(listener);
  }

  /** Start periodic staleness evaluation. */
  start(): void {
    if (this.evalTimer) return;
    this.evalTimer = setInterval(() => this.evaluateAll(), this.evalIntervalMs);
  }

  /** Stop periodic evaluation. */
  stop(): void {
    if (this.evalTimer) {
      clearInterval(this.evalTimer);
      this.evalTimer = null;
    }
  }

  /**
   * Process an incoming presence heartbeat from a peer.
   * Resets the peer's state to "active" and updates last_heartbeat_at.
   */
  receiveHeartbeat(memberId: string, heartbeatAt: string): void {
    const existing = this.peers.get(memberId);
    const oldState = existing?.state ?? "offline";

    const presence: PeerPresence = {
      member_id: memberId,
      state: "active",
      last_heartbeat_at: heartbeatAt,
      evaluated_at: new Date().toISOString(),
    };
    this.peers.set(memberId, presence);

    if (oldState !== "active") {
      this.notifyListeners(memberId, oldState, "active");
    }
  }

  /**
   * Evaluate staleness for all tracked peers and emit state transitions.
   * Called on a timer and exposed for testing.
   */
  evaluateAll(now?: number): void {
    const nowMs = now ?? Date.now();

    for (const [memberId, presence] of this.peers) {
      const lastMs = new Date(presence.last_heartbeat_at).getTime();
      const elapsed = nowMs - lastMs;
      const newState = computePresenceState(elapsed);

      if (newState !== presence.state) {
        const oldState = presence.state;
        presence.state = newState;
        presence.evaluated_at = new Date(nowMs).toISOString();
        this.notifyListeners(memberId, oldState, newState);
      }
    }
  }

  /** Get current presence for a peer. */
  getPresence(memberId: string): PeerPresence | undefined {
    return this.peers.get(memberId);
  }

  /** Get all tracked peers. */
  getAllPresence(): PeerPresence[] {
    return Array.from(this.peers.values());
  }

  /** Remove a peer from tracking (e.g., on node leave). */
  removePeer(memberId: string): void {
    this.peers.delete(memberId);
  }

  private notifyListeners(
    memberId: string,
    oldState: PresenceState,
    newState: PresenceState
  ): void {
    for (const listener of this.listeners) {
      listener(memberId, oldState, newState);
    }
  }
}

/**
 * Compute presence state from elapsed time since last heartbeat.
 * Pure function; no side effects.
 */
export function computePresenceState(elapsedMs: number): PresenceState {
  if (elapsedMs >= PRESENCE_STALENESS.OFFLINE_AFTER_MS) return "offline";
  if (elapsedMs >= PRESENCE_STALENESS.AWAY_AFTER_MS) return "away";
  if (elapsedMs >= PRESENCE_STALENESS.IDLE_AFTER_MS) return "idle";
  return "active";
}

// ═══════════════════════════════════════════════════════════════════════
// Presence publisher (sender side)
// ═══════════════════════════════════════════════════════════════════════

export interface PresencePublisherParams {
  member_id: string;
  emitter_node: string;
  emitter_principal: string;
  fortress_id: string;
  node_private_key: Uint8Array;
  interval_ms?: number;
}

/**
 * Publishes presence heartbeats at a regular interval.
 * The caller provides a publish callback (wired to gossipsub).
 */
export class PresencePublisher {
  private timer: ReturnType<typeof setInterval> | null = null;
  private seq = 0;
  private readonly params: Required<Omit<PresencePublisherParams, "interval_ms">> & {
    interval_ms: number;
  };

  constructor(params: PresencePublisherParams) {
    this.params = {
      ...params,
      interval_ms: params.interval_ms ?? PRESENCE_HEARTBEAT_INTERVAL_MS,
    };
  }

  /** Start publishing. Returns the first heartbeat event immediately. */
  start(publishFn: (event: SignedEvent<PresencePayload>) => void): SignedEvent<PresencePayload> {
    const firstEvent = this.buildHeartbeat();
    publishFn(firstEvent);

    if (this.timer) return firstEvent;
    this.timer = setInterval(() => {
      const evt = this.buildHeartbeat();
      publishFn(evt);
    }, this.params.interval_ms);

    return firstEvent;
  }

  /** Stop publishing. */
  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  /** Build a single heartbeat event. Exposed for testing. */
  buildHeartbeat(): SignedEvent<PresencePayload> {
    this.seq++;
    return packEphemeralEvent<PresencePayload>({
      event_type: "chat_presence",
      emitter_node: this.params.emitter_node,
      emitter_principal: this.params.emitter_principal,
      fortress_id: this.params.fortress_id,
      payload: {
        member_id: this.params.member_id,
        state: "active",
        heartbeat_at: new Date().toISOString(),
        signature_scheme: SIGNATURE_SCHEME_V1,
      },
      monotonic_seq: this.seq,
      node_private_key: this.params.node_private_key,
    });
  }

  isRunning(): boolean {
    return this.timer !== null;
  }
}
