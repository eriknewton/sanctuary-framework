/**
 * Castle Wall audit-event shapes.
 *
 * Every Castle Wall audit event uses `layer: "l1"` (per Codex amendment to
 * scope-lock section 8). The filter daemon emits these over IPC; Sanctuary
 * main writes them to the existing encrypted audit log via AuditLog.append().
 *
 * The shape is a strict superset of Sanctuary's existing AuditEntry: the same
 * required fields plus a Castle Wall typed event_type discriminator on the
 * details object.
 *
 * Source: Castle Wall Phase 1 Scope Lock 2026-05-03 section 8 + Codex
 * amendment 8 (layer "l1" correction; WAL TTL + overflow events).
 */

import { CASTLE_WALL_AUDIT_LAYER, CASTLE_WALL_SCHEMA_VERSION_V1 } from "../constants.js";
import type { DecisionValue } from "../ipc/messages.js";

/**
 * Discriminator for every Castle Wall audit event. Subsequent PRs may add
 * event_type values, but never remove; readers tolerate unknown event_type
 * by logging the event and treating it as a metric / informational entry.
 */
export type CastleWallEventType =
  | "egress_blocked"
  | "egress_allowed"
  | "operator_decision"
  | "policy_loaded"
  | "policy_validation_failed"
  | "filter_started"
  | "filter_stopped"
  | "filter_crashed"
  | "provider_unbound"
  | "queue_saturated"
  | "no_wall_engaged"
  | "no_wall_expired"
  | "wal_overflow"
  | "external_firewall_clobber"
  | "egress_metric_batch";

/** Destination details captured at the time of the event (may be null for non-flow events). */
export interface CastleWallEventDestination {
  host: string | null;
  ip: string;
  port: number;
  protocol: "tcp" | "udp";
}

/** Agent attribution captured at the time of the event (may be null for non-flow events). */
export interface CastleWallEventAgent {
  id: string;
  template: string;
}

/**
 * The canonical Castle Wall audit event. The wire shape MUST be byte-stable
 * under canonical-JSON (see audit/builder.ts) so the daemon-emitted bytes match
 * the Sanctuary-main-stored bytes. PR 6 adds cross-language vector tests.
 */
export interface CastleWallAuditEvent {
  schema_version: typeof CASTLE_WALL_SCHEMA_VERSION_V1;
  layer: typeof CASTLE_WALL_AUDIT_LAYER;
  timestamp: string;
  fortress_id: string;
  event_type: CastleWallEventType;
  agent: CastleWallEventAgent | null;
  destination: CastleWallEventDestination | null;
  decision: DecisionValue | null;
  rule_id: string | null;
  details: Record<string, unknown>;
}
