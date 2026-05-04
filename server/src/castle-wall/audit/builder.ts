/**
 * Builder helpers for CastleWallAuditEvent.
 *
 * Builders are pure: they produce a fully-populated event object with
 * required fields filled and unspecified fields explicitly null. The
 * canonicalize step is a thin wrapper around the federation v0.1 canonical-JSON
 * encoder so daemon-side and main-side serialization stay byte-stable.
 *
 * No I/O. Caller decides where to send the event (over IPC to main, into
 * the daemon WAL on Sanctuary-main-down, or directly to main's AuditLog).
 */

import { canonicalize } from "../../mesh/canonical-json.js";
import { CASTLE_WALL_AUDIT_LAYER, CASTLE_WALL_SCHEMA_VERSION_V1 } from "../constants.js";
import type { DecisionValue } from "../ipc/messages.js";
import type {
  CastleWallAuditEvent,
  CastleWallEventAgent,
  CastleWallEventDestination,
  CastleWallEventType,
} from "./events.js";

/** Optional inputs accepted by the canonical builder. */
export interface BuildEventInput {
  timestamp: string;
  fortress_id: string;
  event_type: CastleWallEventType;
  agent?: CastleWallEventAgent | null;
  destination?: CastleWallEventDestination | null;
  decision?: DecisionValue | null;
  rule_id?: string | null;
  details?: Record<string, unknown>;
}

/** Produce a fully-populated audit event from the supplied inputs. */
export function buildAuditEvent(input: BuildEventInput): CastleWallAuditEvent {
  return {
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    layer: CASTLE_WALL_AUDIT_LAYER,
    timestamp: input.timestamp,
    fortress_id: input.fortress_id,
    event_type: input.event_type,
    agent: input.agent ?? null,
    destination: input.destination ?? null,
    decision: input.decision ?? null,
    rule_id: input.rule_id ?? null,
    details: input.details ?? {},
  };
}

/**
 * Canonical-JSON serialization of the event. This is the byte string the
 * filter daemon writes to the WAL and ships over IPC. Sanctuary main re-runs
 * the canonicalize step to verify byte-for-byte equivalence before persisting.
 */
export function canonicalizeAuditEvent(event: CastleWallAuditEvent): string {
  return canonicalize(event);
}

/** UTF-8 bytes of the canonicalized event. */
export function canonicalizeAuditEventToBytes(event: CastleWallAuditEvent): Uint8Array {
  return new TextEncoder().encode(canonicalizeAuditEvent(event));
}
