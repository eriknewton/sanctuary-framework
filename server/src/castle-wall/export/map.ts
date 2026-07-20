/**
 * CLOSED mapping: a stored `AuditEntry` -> a frozen `EnforcementEvent`, or null.
 *
 * THE HONESTY INVARIANT (this file exists to uphold it): the mapping is a
 * per-class ALLOWLIST. Every output object is constructed field-by-field from a
 * fixed set of explicitly-read keys. The raw audit `details` object is NEVER
 * spread, serialized, or passed through a filter, so a field that is not part of
 * the frozen schema in `./schema.ts` cannot ride out to a collector by accident
 * (AGENTS.md "WHAT THESE TOOLS MUST NEVER DO" #1). A new operator-attribution
 * detail key added to a persisted audit entry is private by default: it reaches
 * an exported event ONLY if someone deliberately adds it to an allowlist here.
 *
 * This mirrors the inversion the agent-facing audit boundary already made
 * (`server/src/operational/agent-audit-redaction.ts`): allowlist, never denylist.
 *
 * Any entry whose operation is not in one of the three forwarded classes maps to
 * `null` and is dropped. An entry that is in a class but whose required fields
 * are missing or malformed also maps to `null` (dropped, never guessed).
 */

import type { AuditEntry } from "../../operational/audit-log.js";
import {
  verifiedCastleWallAuditAttribution,
  type AuditAttributionOptions,
} from "../audit-attribution.js";
import {
  DISTRESS_DETAIL_MAX_CHARS,
  DISTRESS_REASONS,
  DISTRESS_SEVERITIES,
  SANCTUARY_DISTRESS_OPERATION,
  type DistressReason,
  type DistressSeverity,
} from "../../distress/tools.js";
import {
  ENFORCEMENT_EVENT_SCHEMA,
  ENFORCEMENT_POINT_CASTLE_WALL,
  DISTRESS_ENVELOPE_SCHEMA,
  type DistressEvent,
  type EgressDecisionEvent,
  type EnforcementEvent,
  type PolicyChangeEvent,
  type PolicyChangeType,
} from "./schema.js";

/** Stored operation tags that are rule-attributed egress decisions. */
const EGRESS_OPERATIONS = new Set<string>(["egress_blocked", "egress_allowed"]);

/** Stored operation tags that are policy-change events, mapped to a closed change_type. */
const POLICY_CHANGE_OPERATIONS: ReadonlyMap<string, PolicyChangeType> = new Map([
  ["policy_loaded", "loaded"],
  ["policy_validation_failed", "validation_failed"],
  ["castle_wall_observe_promote", "promoted"],
  ["operator_policy_bundle", "bundle"],
  ["operator_decision", "operator_decision"],
]);

/** Stored operation tag for a distress emission (the shared source constant, so a rename cannot drift). */
const DISTRESS_OPERATION = SANCTUARY_DISTRESS_OPERATION;

/**
 * The agent-redaction sentinel. If an upstream (mis)use handed us an
 * agent-redacted entry, a rule-id key can hold this literal; we must never
 * launder it into a "rule id" (property #11). Mirrors per-rule-report.ts.
 */
const REDACTED_SENTINEL = "[redacted]";

/** Control-character class the source distress sanitizer strips; re-applied at the boundary. */
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001F\u007F]+/g;

export type EnforcementEventMapOptions = AuditAttributionOptions;

/** Read a scalar string detail key, or null. Never recurses, never coerces objects. */
function readString(details: Record<string, unknown> | undefined, key: string): string | null {
  if (!details) return null;
  const value = details[key];
  if (typeof value === "string" && value.length > 0 && value !== REDACTED_SENTINEL) {
    return value;
  }
  return null;
}

/** Read a finite-integer detail key, or null. */
function readInteger(details: Record<string, unknown> | undefined, key: string): number | null {
  if (!details) return null;
  const value = details[key];
  if (typeof value === "number" && Number.isFinite(value) && Number.isInteger(value)) {
    return value;
  }
  return null;
}

/** Read the nested `destination` object as a closed record, or undefined. */
function destinationObject(details: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  const dest = details?.destination;
  if (dest && typeof dest === "object" && !Array.isArray(dest)) {
    return dest as Record<string, unknown>;
  }
  return undefined;
}

/**
 * Destination host. Reads the nested `destination.host` (unsigned/channel path)
 * OR the flat `dest_host` (producer-signed body); both are agent-supplied
 * metadata. Returns null when neither is a non-empty string.
 */
function destinationHostOf(details: Record<string, unknown> | undefined): string | null {
  const dest = destinationObject(details);
  const nested = dest ? dest.host : undefined;
  if (typeof nested === "string" && nested.length > 0) return nested;
  return readString(details, "dest_host");
}

function destinationIpOf(details: Record<string, unknown> | undefined): string | null {
  const dest = destinationObject(details);
  const nested = dest ? dest.ip : undefined;
  if (typeof nested === "string" && nested.length > 0) return nested;
  return readString(details, "dest_ip");
}

function destinationPortOf(details: Record<string, unknown> | undefined): number | null {
  const dest = destinationObject(details);
  const nested = dest ? dest.port : undefined;
  if (typeof nested === "number" && Number.isFinite(nested) && Number.isInteger(nested)) {
    return nested;
  }
  return readInteger(details, "dest_port");
}

function destinationProtocolOf(details: Record<string, unknown> | undefined): "tcp" | "udp" | null {
  const dest = destinationObject(details);
  const candidate = (dest ? dest.protocol : undefined) ?? details?.dest_protocol;
  if (candidate === "tcp" || candidate === "udp") return candidate;
  return null;
}

/** Matched rule id. Reads `rule_id` OR the daemon's `rule_id_matched`, or null. */
function ruleIdOf(details: Record<string, unknown> | undefined): string | null {
  if (!details) return null;
  // A redacted rule-id key collapses the whole attribution to null rather than
  // falling through to a sibling key (property #11; mirrors per-rule-report.ts).
  for (const key of ["rule_id", "rule_id_matched"]) {
    if (details[key] === REDACTED_SENTINEL) return null;
  }
  return readString(details, "rule_id") ?? readString(details, "rule_id_matched");
}

/** Map an egress_blocked / egress_allowed entry to a frozen egress-decision event. */
function mapEgressDecision(
  entry: AuditEntry,
  options: EnforcementEventMapOptions = {},
): EgressDecisionEvent | null {
  const attribution = verifiedCastleWallAuditAttribution(entry, options);
  if (attribution === null) return null;

  // Coarse decision is derived from the operation TYPE, not the fine-grained
  // stored `decision` value. The fine-grained value (allow_once / deny_always /
  // timeout_default_deny) is a policy-tier signal; the public schema promises a
  // coarse allow/deny, and the operation tag already carries it unambiguously.
  const decision = entry.operation === "egress_blocked" ? "deny" : "allow";
  const details = entry.details;
  return {
    schema: ENFORCEMENT_EVENT_SCHEMA,
    event_class: "egress_decision",
    timestamp: entry.timestamp,
    decision,
    destination_host: destinationHostOf(details),
    destination_ip: destinationIpOf(details),
    destination_port: destinationPortOf(details),
    destination_protocol: destinationProtocolOf(details),
    rule_id: ruleIdOf(details),
    agent_id: attribution.agentId,
    agent_template: attribution.agentTemplate,
    enforcement_point: ENFORCEMENT_POINT_CASTLE_WALL,
  };
}

/** Map a policy-change entry to a frozen policy-change event. Contents never included. */
function mapPolicyChange(entry: AuditEntry, changeType: PolicyChangeType): PolicyChangeEvent {
  const details = entry.details;
  return {
    schema: ENFORCEMENT_EVENT_SCHEMA,
    event_class: "policy_change",
    timestamp: entry.timestamp,
    change_type: changeType,
    // Coarse attribution only. Each is an OPTIONAL scalar key read explicitly;
    // absence maps to null. No rule text, no manifest body, no allowlist entries.
    signer_ref:
      readString(details, "signer_kid") ??
      readString(details, "signer_key_id") ??
      readString(details, "signer_ref"),
    manifest_digest:
      readString(details, "manifest_digest") ?? readString(details, "manifest_sha256"),
    rule_count:
      readInteger(details, "rule_count") ?? readInteger(details, "loaded_rule_count"),
    enforcement_point: ENFORCEMENT_POINT_CASTLE_WALL,
  };
}

/** Read the closed distress envelope from a stored entry, mapping to the frozen event, or null. */
function mapDistress(entry: AuditEntry): DistressEvent | null {
  const envelope = entry.details?.envelope;
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) return null;
  const record = envelope as Record<string, unknown>;

  // Re-validate every field against the closed vocabularies at the boundary
  // rather than trusting the stored blob. Any deviation drops the event.
  if (record.schema !== DISTRESS_ENVELOPE_SCHEMA) return null;

  const reason = record.reason;
  const severity = record.severity;
  if (typeof reason !== "string" || !DISTRESS_REASONS.includes(reason as DistressReason)) return null;
  if (typeof severity !== "string" || !DISTRESS_SEVERITIES.includes(severity as DistressSeverity)) {
    return null;
  }

  const eventId = record.event_id;
  const actor = record.actor;
  if (typeof eventId !== "string" || eventId.length === 0) return null;
  if (typeof actor !== "string" || actor.length === 0) return null;

  // Detail is already control-stripped + capped at source; re-bound defensively
  // so a tampered stored blob cannot smuggle control bytes or an over-length
  // string past the boundary.
  let detail: string | null = null;
  if (typeof record.detail === "string" && record.detail.length > 0) {
    const cleaned = record.detail.replace(CONTROL_CHARS, " ").trim().slice(0, DISTRESS_DETAIL_MAX_CHARS);
    detail = cleaned.length === 0 ? null : cleaned;
  }

  const sequence =
    typeof record.sequence_in_window === "number" &&
    Number.isFinite(record.sequence_in_window) &&
    Number.isInteger(record.sequence_in_window)
      ? record.sequence_in_window
      : null;

  return {
    schema: ENFORCEMENT_EVENT_SCHEMA,
    event_class: "distress",
    timestamp: entry.timestamp,
    distress_schema: DISTRESS_ENVELOPE_SCHEMA,
    event_id: eventId,
    actor,
    reason: reason as DistressReason,
    severity: severity as DistressSeverity,
    detail,
    sequence_in_window: sequence,
  };
}

/**
 * Map one stored audit entry to a frozen enforcement event, or null if the entry
 * is not one of the three forwarded classes (or is malformed within its class).
 *
 * This is the SINGLE closed mapping surface. It reads only the fields named
 * above; it never spreads `entry.details`.
 */
export function mapAuditEntryToEnforcementEvent(
  entry: AuditEntry,
  options: EnforcementEventMapOptions = {},
): EnforcementEvent | null {
  if (EGRESS_OPERATIONS.has(entry.operation)) {
    return mapEgressDecision(entry, options);
  }
  const changeType = POLICY_CHANGE_OPERATIONS.get(entry.operation);
  if (changeType !== undefined) {
    return mapPolicyChange(entry, changeType);
  }
  if (entry.operation === DISTRESS_OPERATION) {
    return mapDistress(entry);
  }
  return null;
}

/** Map many entries, dropping non-forwarded / malformed ones. Order is preserved. */
export function mapEntriesToEnforcementEvents(
  entries: readonly AuditEntry[],
  options: EnforcementEventMapOptions = {},
): EnforcementEvent[] {
  const events: EnforcementEvent[] = [];
  for (const entry of entries) {
    const mapped = mapAuditEntryToEnforcementEvent(entry, options);
    if (mapped !== null) events.push(mapped);
  }
  return events;
}
