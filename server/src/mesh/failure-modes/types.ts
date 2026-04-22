/**
 * Failure-mode detection — type surface.
 *
 * Spec §8 (failure modes), Architecture Walk Q5 (fifth presence state =
 * `unreachable`).
 *
 * Three high-level shapes:
 *   - `FailureModeAlert` — the per-detection record surfaced to operator UI.
 *   - `MeshHealthSnapshot` — the dashboard-rendered global view.
 *   - `OperatorDecision` — the operator's choice on a flagged decision UI.
 */

import type { NodePresenceState } from "../lifecycle/constants.js";
import type { FailureMode } from "./constants.js";

/** A single failure-mode detection. Stored, surfaced via SSE, audited. */
export interface FailureModeAlert {
  alert_id: string;
  mode: FailureMode;
  /** Node the alert is about. */
  target_node: string;
  /** ms-since-epoch of detection. */
  detected_at: number;
  /** Plain-English explanation per Key 2 / Key 8. */
  message: string;
  /** Mode-specific structured detail. */
  detail: Record<string, unknown>;
  /** Operator-resolution state. */
  resolution: {
    state: "open" | "resolved";
    /** "accept_restored_backup" / "revoke_compromised" / etc. — see ladder. */
    decision?: string;
    decided_at?: number;
    /** Free-form note — operator may attach context for audit. */
    note?: string;
  };
}

/** A node-level row in the dashboard Mesh Health panel. */
export interface MeshHealthNodeRow {
  node_id: string;
  presence: NodePresenceState | "unknown";
  /** Active flagged-failure-modes for this node. */
  flags: FailureMode[];
  /** Mesh-Health rollup. `ok` / `degraded` / `compromised` / `unreachable`. */
  rollup: "ok" | "degraded" | "compromised" | "unreachable" | "left" | "expired";
  /** ms-since-epoch of most recent heartbeat or null. */
  last_heartbeat_at: number | null;
  /** Most recent advertised audit_seq from heartbeat. */
  last_audit_seq: number;
}

/** The dashboard's view of mesh-wide health. */
export interface MeshHealthSnapshot {
  generated_at: number;
  fortress_id: string;
  /** This node's id (the node hosting the dashboard). */
  observer_node: string;
  /** All nodes the observer has seen + their per-node rollup. */
  nodes: MeshHealthNodeRow[];
  /** Currently-open alerts across the mesh. */
  open_alerts: FailureModeAlert[];
  /** Canonical-audit-node id (operator-designated). */
  canonical_audit_node: string;
  /** True iff the canonical audit node has been unreachable past the grace window. */
  canonical_audit_loss: boolean;
}

/** Operator's choice on a flagged detection. */
export interface OperatorDecision {
  alert_id: string;
  decision: string;
  note?: string;
}

/** Split-brain conflict surface — pair of competing policy/locator versions. */
export interface SplitBrainConflict {
  conflict_id: string;
  agent_id: string;
  /** Versioned candidates the operator must choose between. */
  candidates: Array<{
    event_id: string;
    version: number;
    canonical_node: string;
    signed_at: string;
  }>;
  detected_at: number;
}
