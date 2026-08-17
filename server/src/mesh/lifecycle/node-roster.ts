/**
 * NodeRoster — active-node set, per-node public-key pinning, last-heartbeat
 * tracking, and drop-out detection at 3-missed-heartbeats = 90s default.
 *
 * Responsibilities:
 * - Hold every NodeIdentityCertificate the local node has accepted (active,
 *   draining, unreachable, left, revoked, expired).
 * - Provide `lookupNodeCert` for envelope.verifySignedEvent.
 * - Track per-node last-heartbeat timestamp + advertised version vectors.
 * - Detect drop-outs (missed-heartbeats) and expirations (max_offline_window),
 *   emitting events that Follow-up #3 (failure-mode operator surfaces) will
 *   consume.
 *
 * The roster does NOT itself enforce signature verification — it just stores
 * what the orchestrator hands to it. Verification happens at the call sites
 * (envelope.verifySignedEvent before add/update; verifyCertChain on insertion).
 */

import { DEFAULTS, hasReservedCapabilityBits } from "../constants.js";
import { MeshChainError, MeshReservedCapabilityBitError } from "../errors.js";
import {
  NO_AUTHENTICATED_PEER,
  isReservedNodeId,
} from "./envelope-rejection.js";
import type { NodeIdentityCertificate } from "../types.js";
import type { NodePresenceState } from "./constants.js";
import type { DropoutEvent, RosterEntry } from "./types.js";

export type DropoutListener = (e: DropoutEvent) => void;
export type PresenceChangeListener = (
  nodeId: string,
  newState: NodePresenceState,
  prevState: NodePresenceState
) => void;

export interface NodeRosterOptions {
  heartbeat_interval_ms?: number;
  heartbeat_missed_threshold?: number;
  max_offline_window_ms?: number;
}

export class NodeRoster {
  private entries = new Map<string, RosterEntry>();
  private dropoutListeners = new Set<DropoutListener>();
  private presenceListeners = new Set<PresenceChangeListener>();

  private readonly heartbeatIntervalMs: number;
  private readonly missedThreshold: number;
  private readonly maxOfflineWindowMs: number;

  constructor(opts: NodeRosterOptions = {}) {
    this.heartbeatIntervalMs =
      opts.heartbeat_interval_ms ?? DEFAULTS.HEARTBEAT_INTERVAL_MS;
    this.missedThreshold =
      opts.heartbeat_missed_threshold ?? DEFAULTS.HEARTBEAT_MISSED_THRESHOLD;
    this.maxOfflineWindowMs =
      opts.max_offline_window_ms ?? DEFAULTS.MAX_OFFLINE_WINDOW_MS;
  }

  // ── Insertion / removal ─────────────────────────────────────────────

  /**
   * Add a node certificate to the roster. Caller is responsible for having
   * verified the cert chain against the pinned fortress-master before calling.
   * Idempotent on (node_id, principal_signature) — re-adding the same cert is
   * a no-op; re-adding a *different* cert for the same node_id replaces it
   * (operator-rotated key path; existing roster state preserved).
   */
  add(certificate: NodeIdentityCertificate, nowMs: number = Date.now()): void {
    // Defense-in-depth: primary cert verification (verifyCertChain) is the
    // canonical gate for reserved capability bits. This check catches bugs
    // where a caller bypasses or forgets the chain verification step.
    if (hasReservedCapabilityBits(certificate.capabilities)) {
      throw new MeshReservedCapabilityBitError(certificate.capabilities);
    }
    // CHOKEPOINT (rule 5). The roster is what makes a node id AUTHENTICATABLE
    // — `lookupNodeCert` / `lookupActiveNodeCert` are how envelope
    // verification resolves an emitter — so refusing a reserved id here is
    // what establishes, for every downstream consumer, that a verified
    // `emitter_node` is never empty and never the un-attributable sentinel's
    // literal value. Issuance refuses the same ids, and this is the relying
    // side of that pair: a certificate this node did not issue still has to
    // pass here. FAILURE MODE FROM THE OUTSIDE, if this guard is removed: the
    // join is accepted and looks healthy, and the damage shows up much later
    // as an alert whose subject is a peer that shares the "nobody was
    // authenticated" bucket. Predicate: `envelope-rejection.ts`.
    if (isReservedNodeId(certificate.node_id)) {
      throw new MeshChainError(
        `roster refuses a reserved node_id (empty, or the ${NO_AUTHENTICATED_PEER} sentinel)`
      );
    }
    const existing = this.entries.get(certificate.node_id);
    if (existing) {
      // Cert rotation — preserve presence state and heartbeat history but
      // accept the new cert. v0.1 callers MUST have revoked the old cert
      // before rotating; this method does not enforce that.
      existing.certificate = certificate;
      // If a previously-revoked or left node is being re-added with a new
      // cert, that is the rejoin-after-revoke path; v0.1 spec §3.5 forbids
      // it without a fresh join ceremony, so the orchestrator will handle
      // that gating before calling add().
      return;
    }
    const entry: RosterEntry = {
      certificate,
      presence: "joining",
      last_heartbeat_at: 0,
      last_policy_versions: {},
      last_audit_seq: 0,
    };
    this.entries.set(certificate.node_id, entry);
    this.emitPresenceChange(certificate.node_id, "joining", "joining");
    // First-add is also the moment to start the heartbeat window — set
    // last_heartbeat_at to nowMs so we don't immediately flag a brand-new
    // node as missed-heartbeats before it has had a chance to emit one.
    entry.last_heartbeat_at = nowMs;
  }

  /**
   * Mark a node as having reached `active` presence — typically called when
   * the orchestrator observes the new node's first heartbeat (§3.3) or
   * completes the initial sync (§3.2).
   */
  markActive(nodeId: string): void {
    const entry = this.entries.get(nodeId);
    if (!entry) return;
    if (entry.presence !== "active") {
      const prev = entry.presence;
      entry.presence = "active";
      this.emitPresenceChange(nodeId, "active", prev);
    }
  }

  markDraining(nodeId: string): void {
    const entry = this.entries.get(nodeId);
    if (!entry) return;
    const prev = entry.presence;
    entry.presence = "draining";
    this.emitPresenceChange(nodeId, "draining", prev);
  }

  markLeft(nodeId: string, nowMs: number = Date.now()): void {
    const entry = this.entries.get(nodeId);
    if (!entry) return;
    const prev = entry.presence;
    entry.presence = "left";
    entry.ended_at = nowMs;
    this.emitPresenceChange(nodeId, "left", prev);
  }

  markRevoked(nodeId: string, nowMs: number = Date.now()): void {
    const entry = this.entries.get(nodeId);
    if (!entry) return;
    const prev = entry.presence;
    entry.presence = "revoked";
    entry.ended_at = nowMs;
    this.emitPresenceChange(nodeId, "revoked", prev);
  }

  markExpired(nodeId: string, nowMs: number = Date.now()): void {
    const entry = this.entries.get(nodeId);
    if (!entry) return;
    const prev = entry.presence;
    entry.presence = "expired";
    entry.ended_at = nowMs;
    this.emitPresenceChange(nodeId, "expired", prev);
  }

  // ── Heartbeat ingestion ──────────────────────────────────────────────

  /**
   * Record a verified heartbeat from a node. The orchestrator MUST have
   * verified the heartbeat envelope's signature before calling this.
   */
  recordHeartbeat(params: {
    node_id: string;
    at_ms: number;
    policy_versions: Record<string, number>;
    audit_seq: number;
    advertised_state: "active" | "draining" | "gated_closed";
  }): void {
    const entry = this.entries.get(params.node_id);
    if (!entry) return;
    entry.last_heartbeat_at = params.at_ms;
    entry.last_policy_versions = params.policy_versions;
    entry.last_audit_seq = params.audit_seq;
    if (entry.presence === "joining" && params.advertised_state === "active") {
      this.markActive(params.node_id);
    } else if (
      entry.presence === "unreachable" &&
      params.advertised_state === "active"
    ) {
      const prev = entry.presence;
      entry.presence = "active";
      this.emitPresenceChange(params.node_id, "active", prev);
    } else if (params.advertised_state === "draining") {
      this.markDraining(params.node_id);
    }
  }

  /**
   * Iterate the roster looking for nodes whose last heartbeat is older than
   * the missed-threshold × interval. Promotes them to `unreachable` and emits
   * a DropoutEvent. Idempotent — already-unreachable nodes are not re-emitted.
   *
   * Also promotes long-offline nodes to `expired` past `max_offline_window_ms`
   * (§3.5).
   */
  checkDropouts(nowMs: number = Date.now()): DropoutEvent[] {
    const dropoutThresholdMs =
      this.heartbeatIntervalMs * this.missedThreshold;
    const events: DropoutEvent[] = [];

    for (const [nodeId, entry] of this.entries) {
      if (
        entry.presence === "left" ||
        entry.presence === "revoked" ||
        entry.presence === "expired"
      ) {
        continue;
      }
      const sinceHeartbeat = nowMs - entry.last_heartbeat_at;

      if (
        entry.presence !== "unreachable" &&
        sinceHeartbeat >= dropoutThresholdMs
      ) {
        const prev = entry.presence;
        entry.presence = "unreachable";
        const e: DropoutEvent = {
          node_id: nodeId,
          detected_at: nowMs,
          reason: "missed_heartbeats",
          last_seen_at: entry.last_heartbeat_at,
        };
        events.push(e);
        this.emitPresenceChange(nodeId, "unreachable", prev);
        this.emitDropout(e);
      }

      if (
        entry.presence === "unreachable" &&
        sinceHeartbeat >= this.maxOfflineWindowMs
      ) {
        const prev = entry.presence;
        entry.presence = "expired";
        entry.ended_at = nowMs;
        const e: DropoutEvent = {
          node_id: nodeId,
          detected_at: nowMs,
          reason: "expired_offline_window",
          last_seen_at: entry.last_heartbeat_at,
        };
        events.push(e);
        this.emitPresenceChange(nodeId, "expired", prev);
        this.emitDropout(e);
      }
    }
    return events;
  }

  // ── Read-only queries ────────────────────────────────────────────────

  lookupNodeCert(nodeId: string): NodeIdentityCertificate | undefined {
    return this.entries.get(nodeId)?.certificate;
  }

  /**
   * Looks up only certs that are still trust-eligible — i.e., not revoked.
   * Used by the orchestrator's verify-and-dispatch path so that a revoked
   * node's signed events are rejected immediately (§3.6).
   */
  lookupActiveNodeCert(nodeId: string): NodeIdentityCertificate | undefined {
    const entry = this.entries.get(nodeId);
    if (!entry) return undefined;
    if (entry.presence === "revoked" || entry.presence === "expired") {
      return undefined;
    }
    return entry.certificate;
  }

  presenceOf(nodeId: string): NodePresenceState | undefined {
    return this.entries.get(nodeId)?.presence;
  }

  size(): number {
    return this.entries.size;
  }

  listAll(): RosterEntry[] {
    return [...this.entries.values()];
  }

  listByPresence(presence: NodePresenceState): RosterEntry[] {
    return [...this.entries.values()].filter((e) => e.presence === presence);
  }

  // ── Listener wiring ──────────────────────────────────────────────────

  onDropout(listener: DropoutListener): () => void {
    this.dropoutListeners.add(listener);
    return () => this.dropoutListeners.delete(listener);
  }

  onPresenceChange(listener: PresenceChangeListener): () => void {
    this.presenceListeners.add(listener);
    return () => this.presenceListeners.delete(listener);
  }

  private emitDropout(e: DropoutEvent): void {
    for (const l of this.dropoutListeners) l(e);
  }

  private emitPresenceChange(
    nodeId: string,
    next: NodePresenceState,
    prev: NodePresenceState
  ): void {
    for (const l of this.presenceListeners) l(nodeId, next, prev);
  }
}
