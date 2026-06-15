/**
 * Agent-facing audit redaction (property #11, no-policy-inference).
 *
 * This is the SINGLE source of truth for which audit-detail keys are
 * policy-inference-sensitive and must be stripped before an audit entry crosses
 * an agent-facing boundary. It is shared by every agent-facing audit surface so
 * that adding one sensitive key here closes ALL of them at once:
 *
 *   - `monitor_audit_log` (server/src/index.ts) — the agent-facing audit READ.
 *   - `sanctuary_audit_search` (server/src/agent-native/cooperative-surface.ts)
 *     — the agent-facing audit SEARCH. The search must build its match corpus
 *     from the REDACTED projection produced here, not from the raw entry, or a
 *     redacted field becomes a probing oracle: an agent could guess a `rule_id`
 *     (etc.) and learn a match differentially from `result_count` even though
 *     the returned rows omit details (property #11 violation).
 *
 * The OPERATOR audit path (the CLI audit-dump / per-rule read-out in
 * server/src/castle-wall/audit/per-rule-report.ts) is full-fidelity and MUST
 * NOT use this redaction — operators are authorized to see the deciding rule.
 *
 * Single-sourcing matters most when producer-signing activates: the moment a
 * new operator-only field lands in the persisted entry, it must be added to
 * AUDIT_AGENT_REDACT_DETAIL_KEYS here once, and both the read and the search
 * surface close together.
 */

import type { AuditEntry } from "./audit-log.js";
import { CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY } from "../castle-wall/constants.js";

export const AUDIT_AGENT_REDACTED = "[redacted]";

export const AUDIT_AGENT_REDACT_DETAIL_KEYS = new Set([
  "decided_by",
  "identity_id",
  "operatorId",
  "operator_id",
  "resolved_by",
  "policy_rule_id",
  // Castle Wall matched-rule id (#381). Written to the stored audit entry for
  // operator attribution; redacted here so an agent querying audit entries
  // cannot learn which allow/deny rule matched and map the essentials list by
  // probing (property #11, no-policy-inference).
  "rule_id",
  // The Linux producer-signed audit path persists the matched rule under
  // `rule_id_matched` (the Rust daemon's body, see audit-consumer.ts
  // buildDetailsForEvent / WAL_OPERATION_TO_EVENT_TYPE). It carries the same
  // operator-only attribution as `rule_id` and MUST be redacted on the
  // agent-facing read path for the same property-#11 reason; without this an
  // agent could read the matched rule off a signed entry (pre-existing leak
  // since #520, closed here).
  "rule_id_matched",
  "policy_match",
  "policy_decision",
  "policy_tier",
  "tier",
  // Linux producer-signed decision provenance. `buildDetailsForEvent`
  // (castle-wall/runtime/audit-consumer.ts) spreads the signed body's own
  // `details` into the persisted entry, so the daemon's `decision_provenance`
  // lands as a TOP-LEVEL detail key. It records WHY/HOW the allow/deny resolved
  // (the policy reasoning path), so it is policy-inference-sensitive in exactly
  // the property-#11 sense and is operator/auditor-only. Redact it on the
  // agent-facing read path alongside `rule_id_matched`.
  "decision_provenance",
  // The producer-signed canonical blob (`cw_producer_signed_canonical`) is the
  // VERBATIM signed JSON body persisted as a STRING. Key-based redaction does
  // not reach inside a string, so without redacting the whole value an agent
  // reading a signed entry recovers the matched rule (and `decision_provenance`,
  // `agent_id`, `dest_*`) embedded in that body — a deeper no-policy-inference
  // leak than the top-level `rule_id_matched` (property #11). Agents never need
  // the signature-verification blob (re-verification is operator/auditor-side),
  // so redacting the whole value is correct. Imported from constants.ts so the
  // wire-constant literal is not duplicated.
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
]);

export function redactAuditValueForAgent(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => redactAuditValueForAgent(item));
  }
  if (value && typeof value === "object") {
    const redacted: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
      redacted[key] = AUDIT_AGENT_REDACT_DETAIL_KEYS.has(key)
        ? AUDIT_AGENT_REDACTED
        : redactAuditValueForAgent(nested);
    }
    return redacted;
  }
  return value;
}

export function redactAuditEntryForAgent(entry: AuditEntry): AuditEntry {
  return {
    ...entry,
    identity_id: AUDIT_AGENT_REDACTED,
    details: entry.details
      ? (redactAuditValueForAgent(entry.details) as Record<string, unknown>)
      : undefined,
  };
}

/**
 * The agent-redacted detail projection used as the SEARCH corpus for the
 * agent-facing `sanctuary_audit_search`. Returns the entry's `details` with
 * every policy-inference-sensitive key replaced by the redaction sentinel, so
 * searching/filtering over it can never differentially hit a redacted field's
 * real value — closing the no-policy-inference probing oracle (property #11).
 *
 * Returns an empty object for entries with no details, so callers can build a
 * stable corpus string without special-casing.
 */
export function redactAuditDetailsForAgent(
  entry: Pick<AuditEntry, "details">
): Record<string, unknown> {
  if (!entry.details) return {};
  return redactAuditValueForAgent(entry.details) as Record<string, unknown>;
}
