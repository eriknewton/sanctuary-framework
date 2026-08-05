/**
 * FROZEN public enforcement-event schema: `sanctuary.enforcement-event.v1`.
 *
 * This is the PUBLIC CONTRACT a third-party operator console (for example a
 * Palo Alto Cortex XSIAM content pack) builds its data-modeling rules against.
 * It is deliberately a CLOSED, versioned shape: every field is operation
 * METADATA only. No state content, no keys, no policy contents, no raw audit
 * `details` ever appear here (AGENTS.md "WHAT THESE TOOLS MUST NEVER DO" #1).
 *
 * VERSIONING PROMISE (additive-only, like `CastleWallAuditEvent`):
 *   - The `schema` discriminator string is FROZEN at
 *     `sanctuary.enforcement-event.v1`. A breaking change mints a `.v2` string;
 *     it never reinterprets a v1 field.
 *   - New OPTIONAL metadata fields may be ADDED to a class in a later minor
 *     revision; existing fields are never removed or repurposed.
 *   - The three `event_class` values are a CLOSED set for v1. A new class is an
 *     additive change a consumer tolerates by ignoring unknown classes.
 *
 * WHY A CLOSED SHAPE AND NOT RAW `details`: the audit `details` object can carry
 * free-text `reason` strings that historically leaked anomaly thresholds
 * (`server/src/operational/agent-audit-redaction.ts` documents four such leaks).
 * The operator is entitled to that context, but the exporter emits this DEFINED
 * shape rather than serializing `details`, so nothing rides along by accident.
 * The mapper in `./map.ts` constructs these objects field-by-field from an
 * explicit allowlist and NEVER spreads `details`.
 */

import type { DistressReason, DistressSeverity } from "../../distress/tools.js";

/**
 * The FROZEN schema discriminator carried by every exported event.
 *
 * This is the SOLE declaration of the literal in `server/src`. The batch
 * envelope `HttpCollectorSink` POSTs in `./sink.ts` tags itself with this same
 * constant by import, so envelope and events can never announce different
 * versions.
 *
 * `test/structure/cross-file-contract-pins.test.ts` walks EVERY .ts file under
 * `server/src` over RAW source and fails on any occurrence of this string
 * written as a QUOTED literal outside this declaration. Its allowlist is empty.
 *
 * What that scan does NOT see, stated because an earlier version of this
 * comment claimed more than the code did: a bare, unquoted mention. Both
 * `cli/cortex-export.ts` (operator `--help` text) and `./README.md` spell the
 * version bare, so neither is detected, and neither is a declaration. Both are
 * descriptions that must be updated alongside a version bump, and nothing
 * mechanical will remind you.
 *
 * Why the scan and not just this comment: a re-typed copy is how a `.v2` mint
 * ships a half-migrated stream, and a consumer keying its ingestion rules off
 * the version would mis-model the batch without any error surfacing on either
 * side.
 */
export const ENFORCEMENT_EVENT_SCHEMA = "sanctuary.enforcement-event.v1" as const;

/** The FROZEN distress-envelope schema string this exporter forwards verbatim. */
export const DISTRESS_ENVELOPE_SCHEMA = "sanctuary.distress.v1" as const;

/** Enforcement point that produced the decision. Closed for v1. */
export const ENFORCEMENT_POINT_CASTLE_WALL = "castle_wall" as const;
export type EnforcementPoint = typeof ENFORCEMENT_POINT_CASTLE_WALL;

/** The three CLOSED event classes forwarded in v1. */
export type EnforcementEventClass = "egress_decision" | "policy_change" | "distress";

/** Coarse, public egress outcome. Deliberately 2-valued (no policy-tier granularity). */
export type ExportedEgressDecision = "allow" | "deny";

/** Closed set of policy-change kinds v1 forwards. */
export const POLICY_CHANGE_TYPES = [
  "loaded",
  "validation_failed",
  "promoted",
  "bundle",
  "operator_decision",
] as const;
export type PolicyChangeType = (typeof POLICY_CHANGE_TYPES)[number];

/** Fields shared by every exported event. */
export interface EnforcementEventBase {
  /** FROZEN discriminator. Always {@link ENFORCEMENT_EVENT_SCHEMA}. */
  schema: typeof ENFORCEMENT_EVENT_SCHEMA;
  /** Which of the three closed classes this event is. */
  event_class: EnforcementEventClass;
  /** ISO-8601 timestamp the underlying audit entry was recorded at. */
  timestamp: string;
}

/**
 * A rule-attributed egress allow/deny decision. Every field is metadata the
 * agent itself targeted (destination) or operator-owned policy attribution
 * (rule id, decision) the OPERATOR is authorized to forward.
 */
export interface EgressDecisionEvent extends EnforcementEventBase {
  event_class: "egress_decision";
  /** Coarse allow/deny, derived from the enforcement event TYPE (not the fine-grained policy decision). */
  decision: ExportedEgressDecision;
  /** The host the agent targeted, or null if the entry recorded none. */
  destination_host: string | null;
  /** The resolved IP the agent targeted, or null. */
  destination_ip: string | null;
  /** The destination port, or null. */
  destination_port: number | null;
  /** Transport protocol, or null. */
  destination_protocol: "tcp" | "udp" | null;
  /** The policy rule id that decided the flow, or null for a baseline default-deny. */
  rule_id: string | null;
  /**
   * Verified subject attribution. Linux signed rows usually carry the
   * operator-facing agent id (for example "claude-code-1"); macOS signed rows
   * can carry the fortress-scoped protection subject (for example
   * `<fortress>/uid-501`) because the OS audit token is the signed subject. The
   * field name and scalar shape are frozen. NEVER a key, DID, or secret.
   */
  agent_id: string | null;
  /** The agent role / template (for example "coding-assistant"). */
  agent_template: string | null;
  /** Where the decision was enforced. */
  enforcement_point: EnforcementPoint;
}

/**
 * A policy-change event. Carries the KIND of change and coarse attribution
 * (signer reference, digest, rule count) only. It NEVER carries policy
 * contents, rule text, or allowlist entries.
 */
export interface PolicyChangeEvent extends EnforcementEventBase {
  event_class: "policy_change";
  /** What kind of policy transition occurred. Closed set. */
  change_type: PolicyChangeType;
  /** Signer key id / reference for the change, or null. NEVER a private key. */
  signer_ref: string | null;
  /** Digest of the loaded manifest/bundle, or null. NEVER the manifest contents. */
  manifest_digest: string | null;
  /** Number of rules in the loaded policy, or null. A count only, never the rules. */
  rule_count: number | null;
  /** Where the change was applied. */
  enforcement_point: EnforcementPoint;
}

/**
 * A distress beacon, forwarded from the closed `sanctuary.distress.v1` envelope
 * (`server/src/distress/tools.ts`). The envelope is already a closed,
 * control-stripped, capped shape that travels to an operator destination by
 * design; the exporter re-validates every field against the closed vocabularies
 * at the boundary rather than trusting the stored blob.
 */
export interface DistressEvent extends EnforcementEventBase {
  event_class: "distress";
  /** FROZEN inner schema string. Always {@link DISTRESS_ENVELOPE_SCHEMA}. */
  distress_schema: typeof DISTRESS_ENVELOPE_SCHEMA;
  /** The distress envelope's own event id. */
  event_id: string;
  /** The acting identity id the envelope named. */
  actor: string;
  /** Closed reason enum value. */
  reason: DistressReason;
  /** Closed severity enum value. */
  severity: DistressSeverity;
  /** Sanitized, hard-capped free-text context, or null. Bounded at source AND re-bounded here. */
  detail: string | null;
  /** 1-based position in the rolling rate-limit window, or null. */
  sequence_in_window: number | null;
}

/** The closed union a consumer of `sanctuary.enforcement-event.v1` receives. */
export type EnforcementEvent = EgressDecisionEvent | PolicyChangeEvent | DistressEvent;
