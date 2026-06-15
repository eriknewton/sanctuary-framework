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
 *     via `buildAgentSearchCorpus` here, which OMITS the sensitive keys entirely,
 *     not from the raw entry (and not from an in-place redaction either), or a
 *     sensitive field becomes a probing oracle: an agent could guess a `rule_id`
 *     value — OR probe the sensitive key NAME / the `[redacted]` sentinel that an
 *     in-place projection would leave behind — and learn a match differentially
 *     from `result_count` even though the returned rows omit details
 *     (property #11 violation).
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
 * Recursively DROP every policy-inference-sensitive key from a details value,
 * keeping non-sensitive keys (and recursing into their nested values). Unlike
 * `redactAuditValueForAgent`, which replaces a sensitive value IN PLACE with the
 * `[redacted]` sentinel, this removes the key/value pair ENTIRELY: neither the
 * sensitive key NAME nor the sentinel string survives. Arrays are mapped through
 * element-wise; non-object scalars pass through unchanged.
 */
function dropAgentSensitiveDetailKeys(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => dropAgentSensitiveDetailKeys(item));
  }
  if (value && typeof value === "object") {
    const projected: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
      if (AUDIT_AGENT_REDACT_DETAIL_KEYS.has(key)) continue;
      projected[key] = dropAgentSensitiveDetailKeys(nested);
    }
    return projected;
  }
  return value;
}

/**
 * Build the agent-facing SEARCH corpus projection of an entry's `details` for
 * `sanctuary_audit_search`. Every policy-inference-sensitive key in
 * AUDIT_AGENT_REDACT_DETAIL_KEYS is OMITTED entirely — its key name, its value,
 * AND the `[redacted]` sentinel are all absent from the result.
 *
 * Omitting (rather than redacting-in-place) closes the residual presence oracle
 * left by an in-place projection: with `rule_id` -> `[redacted]` the key name
 * `"rule_id"` and the literal `"[redacted]"` both stay in the search string, so
 * an agent could probe for a sensitive key name OR the sentinel and read a
 * differential `result_count`, learning WHICH entries carry a policy-sensitive
 * field even though it never recovers the value (property #11, no-policy-
 * inference). After this projection a probe for a sensitive key name, the
 * sentinel, or a sensitive value yields no differential match; non-sensitive
 * fields (e.g. `operation`, `dest_host`, `decision`) stay searchable.
 *
 * Returns an empty object for entries with no details, so callers can build a
 * stable corpus string without special-casing. Reuses the single-sourced
 * AUDIT_AGENT_REDACT_DETAIL_KEYS set: adding a key there closes the read, the
 * in-place redaction, AND this search corpus together. The OPERATOR audit-search
 * path stays full-fidelity and MUST NOT use this projection.
 */
export function buildAgentSearchCorpus(
  entry: Pick<AuditEntry, "details">
): Record<string, unknown> {
  if (!entry.details) return {};
  return dropAgentSensitiveDetailKeys(entry.details) as Record<string, unknown>;
}
