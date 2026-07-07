/**
 * Agent-facing audit redaction (property #11, no-policy-inference) — ALLOWLIST.
 *
 * THE INVERSION (CISO HIGH-1 / 2026-06-15): this module used to carry a DENYLIST
 * (`AUDIT_AGENT_REDACT_DETAIL_KEYS`) of the audit-`details` keys that must be
 * stripped before an entry crosses an agent-facing boundary. A denylist is
 * fragile-by-construction: every NEW operator-attribution field added to a
 * persisted audit entry ships to the agent unless someone remembers to extend a
 * hidden list in another file. It leaked four times that way, and a LIVE leak
 * remained: the free-text `reason` field (never on the denylist) carried anomaly
 * THRESHOLDS verbatim ("Signing frequency (7/min) exceeds limit (5/min)", "…
 * threshold: 50", "3× above average", "not classified in any policy tier"),
 * letting an agent read its own detection thresholds and operate just under them.
 *
 * The durable fix is to INVERT to an ALLOWLIST. Agent-facing audit surfaces now
 * emit ONLY a fixed, explicitly-safe shape and NEVER pass `details` through any
 * field-name filter. A new operator-attribution field added to a persisted entry
 * is private by default — it can only reach an agent if someone deliberately adds
 * it to one of the allowlists here. This is the single source of truth for both:
 *
 *   - The agent-facing audit READ shape (`AGENT_AUDIT_VIEW_FIELDS`), used by
 *     `monitor_audit_log` (server/src/index.ts), `audit_export_siem`
 *     (server/src/audit/*), and the cooperative pull/search surfaces
 *     (server/src/agent-native/cooperative-surface.ts).
 *   - The agent-facing SEARCH corpus (`AGENT_AUDIT_SEARCHABLE_DETAIL_KEYS`),
 *     used by `sanctuary_audit_search`. The search needle is matched ONLY against
 *     the operation name plus this curated, non-policy-inference subset of detail
 *     keys — never the raw entry — so a probe for a policy-sensitive value, key
 *     name, or sentinel can never differentially match off `result_count`
 *     (property #11, no-policy-inference).
 *
 * The OPERATOR audit path (the CLI audit-dump / per-rule read-out in
 * server/src/castle-wall/audit/per-rule-report.ts, the dashboard, and raw
 * `auditLog.query`) is full-fidelity and MUST NOT use this redaction — operators
 * own the policy and are authorized to see the deciding rule, the tier, and the
 * reason.
 */

import type { AuditEntry } from "./audit-log.js";

/**
 * The ONLY fields an agent-facing audit READ may expose from an entry. Anything
 * not in this set — every `details` field, the `identity_id`, the `layer` — is
 * withheld by construction. `has_details` is a coarse boolean so an agent can
 * tell an entry carried operator-side detail without learning what it was.
 */
export const AGENT_AUDIT_VIEW_FIELDS = [
  "timestamp",
  "operation",
  "result",
  "has_details",
] as const;

/**
 * The agent-facing, redacted view of a single audit entry. Fixed shape; carries
 * no `details`, no `identity_id`, no policy attribution.
 */
export interface AgentAuditView {
  timestamp: string;
  operation: string;
  /**
   * `"pending"` is a durable, pre-access audit state (currently only the
   * governed file-grant mint's pre-placement audit) -- honest to expose as-is
   * since it reveals only literal completion state, no policy internals.
   */
  result: "success" | "failure" | "pending";
  has_details: boolean;
}

/**
 * Redact an audit entry for agent consumption. Returns ONLY the allowlisted
 * fixed shape — timestamp, operation, result, and a coarse has_details flag.
 *
 * Unlike the retired denylist projection, this never iterates `details` and
 * never copies a `details` field through a filter: a field can only reach an
 * agent by being one of the four allowlisted top-level fields. Adding a new
 * operator-attribution detail key therefore CANNOT regress into an agent leak.
 */
export function redactAuditEntryForAgent(entry: AuditEntry): AgentAuditView {
  return {
    timestamp: entry.timestamp,
    operation: entry.operation,
    result: entry.result,
    has_details: !!entry.details,
  };
}

/**
 * Curated allowlist of `details` keys that are SAFE to expose to the agent-facing
 * audit SEARCH corpus. These are values the calling agent already supplied — the
 * egress destination it itself targeted — and which carry no policy-inference
 * signal (no rule id, no tier, no threshold, no decision granularity, no
 * decision-provenance). Everything NOT listed here — including the free-text
 * `reason`, the fine-grained `decision`, every `*rule_id*`, `tier`/`policy_*`,
 * `decision_provenance`, and the producer-signed canonical blob — is omitted from
 * the search corpus entirely, so it is neither returned NOR differentially
 * probeable.
 *
 * `decision` was DELIBERATELY REMOVED (CISO HIGH, 2026-06-16): although the agent
 * observes the coarse allow/deny of its own call, the persisted `decision` is
 * fine-grained (`allow_once`/`allow_always`/`deny_once`/`deny_always`/
 * `timeout_default_deny`, castle-wall/ipc/messages.ts). Indexing it let a
 * cooperative agent probe `result_count` to learn WHICH policy disposition fired
 * (e.g. an always-rule vs a once-prompt, or a timeout default-deny) — a
 * policy-inference oracle. The agent already knows pass/fail from its own call
 * result; the granularity is the operator's policy and stays off the corpus.
 *
 * Keep this list TINY and obviously-safe. The bar for adding a key: the agent
 * itself supplied the value, and the value reveals nothing about the operator's
 * policy. When in doubt, leave it out — that is the whole point of an allowlist.
 */
export const AGENT_AUDIT_SEARCHABLE_DETAIL_KEYS = new Set<string>([
  // The egress destination the agent itself targeted. The agent supplied this;
  // it is not operator policy.
  "dest_host",
  "destination",
]);

/**
 * Build the agent-facing SEARCH corpus projection of an entry's `details`. Only
 * keys in AGENT_AUDIT_SEARCHABLE_DETAIL_KEYS survive (their scalar values are
 * kept; nested values are dropped — the searchable keys are all scalars). Every
 * other key — its name, its value, and any nested content — is OMITTED entirely.
 *
 * Because this is an ALLOWLIST, a probe for a policy-sensitive value, a sensitive
 * key NAME, or any redaction sentinel yields no differential match: the field is
 * simply absent from the corpus whether or not the entry carried it (property
 * #11, no-policy-inference). A new operator-attribution field added to the
 * persisted entry is NOT searchable unless it is deliberately allowlisted here.
 *
 * Returns an empty object for entries with no details so callers can build a
 * stable corpus string without special-casing. The OPERATOR audit-search path
 * stays full-fidelity and MUST NOT use this projection.
 */
export function buildAgentSearchCorpus(
  entry: Pick<AuditEntry, "details">
): Record<string, unknown> {
  if (!entry.details) return {};
  const projected: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(entry.details)) {
    if (!AGENT_AUDIT_SEARCHABLE_DETAIL_KEYS.has(key)) continue;
    // Only scalar values are searchable. A non-scalar under an allowlisted key
    // is dropped rather than recursed, so no nested key/value can ride in.
    if (value === null || typeof value !== "object") {
      projected[key] = value;
    }
  }
  return projected;
}
