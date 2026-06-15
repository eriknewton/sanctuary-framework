/**
 * Per-rule-per-flow audit READ-OUT (operator-facing legibility surface).
 *
 * Castle Wall already RECORDS the deciding rule for every enforced flow: the
 * Rust daemon stamps `details.rule_id_matched` (castle-wall-daemon/src/policy.rs)
 * and the macOS extension path stamps `details.rule_id`
 * (server/src/castle-wall/runtime/macos-flow-events.ts). This module is the
 * read-out over those ALREADY-RECORDED entries — it attributes each flow to the
 * rule that decided it and rolls flows up per rule. It adds NO emission, NO
 * schema field, NO enforcement behavior, and NO wire/at-rest change; it is a
 * pure function over `AuditEntry[]` the caller has already loaded and decrypted.
 *
 * WHAT IT IS NOT (read this before extending):
 *   - It is NOT tamper-evidence. It reads recorded attribution; it does not make
 *     the trail unforgeable. Unforgeability (producer-signed audit activation) is
 *     a separate, currently-inert capability — never imply otherwise here or in
 *     any operator-facing string derived from this module.
 *   - It never fabricates a rule. A flow whose deciding verdict matched no rule
 *     (a baseline default-deny, or a fail-closed audit-WAL-append-failed verdict)
 *     is recorded with a null rule id and rolls into an explicit DEFAULT_DENY
 *     bucket — never invented as some rule.
 *
 * SECURITY (property #11, no-policy-inference): the `ruleId` this module exposes
 * is operator-only. The redaction of `rule_id` / `rule_id_matched` happens at the
 * agent-facing read boundaries (AUDIT_AGENT_REDACT_DETAIL_KEYS in
 * server/src/index.ts and the cooperative-surface tools). This module is a pure
 * aggregator with no read-boundary of its own; callers MUST only hand it
 * operator-context entries. The operator CLI is such a caller; an agent-facing
 * tool is not and must not call it on raw (unredacted) entries.
 */

import type { AuditEntry } from "../../l2-operational/audit-log.js";
import type { DecisionValue } from "../ipc/messages.js";

/**
 * Sentinel bucket id for flows whose deciding verdict matched NO rule (baseline
 * default-deny, or the fail-closed audit-WAL-append-failed dispatch). This is a
 * synthetic grouping key for the read-out only; it is NEVER written back to any
 * audit entry and is NEVER a real rule id (a real rule id is operator-authored
 * policy text). Rendered to the operator as an explicit "no matching rule" line.
 */
export const DEFAULT_DENY_BUCKET = "(default-deny: no matching rule)" as const;

/** Coarse decision category a flow resolved to, derived from the stored entry. */
export type FlowDecisionCategory = "allow" | "deny" | "prompt";

/** The stored-entry detail keys that carry the matched rule id, in priority order. */
const RULE_ID_DETAIL_KEYS = ["rule_id", "rule_id_matched"] as const;

/**
 * Castle Wall stored `operation` tags that represent an enforced/observed FLOW
 * (a packet/connection the wall decided on). Non-flow lifecycle events
 * (filter_started, policy_loaded, ...) are not flows and are excluded from the
 * per-rule read-out. These are the NORMALIZED stored tags
 * (audit-consumer maps the daemon's egress_approved/egress_pending onto these).
 *
 * NO DOUBLE-COUNT (verified against the recorded lifecycle, not assumed):
 * `operator_decision` is the normalized tag for the Linux daemon's
 * `egress_pending` verdict (audit-consumer WAL_OPERATION_TO_EVENT_TYPE). A
 * `PromptRequired` verdict in the current daemon is terminal-on-the-packet: the
 * nfqueue verdict loop maps it to `NfVerdict::Drop` (castle-wall-daemon/src/
 * nfqueue.rs ~438) and `evaluate_attempt` emits exactly ONE WAL event per
 * packet. There is no prompt-and-wait re-evaluation that would write a SECOND
 * terminal `egress_approved`/`egress_blocked` event for the same flow (the
 * approval.rs module only coalesces prompt EMISSION; it never re-evaluates or
 * emits a terminal verdict). On the macOS path, `flow_pending_approval` writes
 * NO audit entry at all (it only enqueues); only the terminal
 * `flow_decision_recorded` writes one `egress_allowed`/`egress_blocked`. So a
 * single flow is recorded once — either as one `operator_decision` (Linux
 * prompt-drop) or one terminal entry — never both. Counting all three tags here
 * therefore counts each flow exactly once. If a future build adds a real
 * prompt-resolution that emits a terminal event keyed to the same flow, this
 * set (and the counting) MUST be revisited to dedupe prompt+resolution pairs.
 */
const FLOW_OPERATIONS = new Set<string>([
  "egress_allowed",
  "egress_blocked",
  "operator_decision",
]);

/** Map a stored `operation` tag to its decision category (the structural fallback). */
function categoryFromOperation(operation: string): FlowDecisionCategory | null {
  switch (operation) {
    case "egress_allowed":
      return "allow";
    case "egress_blocked":
      return "deny";
    case "operator_decision":
      // An operator_decision entry without a terminal `decision` detail is a
      // prompt event (a flow was surfaced for approval). When it carries a
      // terminal decision, the detail-derived category below takes precedence.
      return "prompt";
    default:
      return null;
  }
}

/** Map a recorded `DecisionValue` to its coarse category. Authoritative when present. */
function categoryFromDecisionValue(
  decision: DecisionValue
): FlowDecisionCategory {
  switch (decision) {
    case "allow_once":
    case "allow_always":
      return "allow";
    case "deny_once":
    case "deny_always":
    case "timeout_default_deny":
      return "deny";
  }
}

/** The agent-redaction sentinel. A detail key holding this is operator-stripped. */
const REDACTED_SENTINEL = "[redacted]";

/** Extract the matched rule id from a stored entry's details, or null if none. */
function ruleIdOf(entry: AuditEntry): string | null {
  const details = entry.details;
  if (!details) return null;
  // A redacted value ("[redacted]") only ever appears if a caller fed
  // agent-redacted entries in. That is a misuse this module refuses to launder
  // into a "rule" — and crucially, a redacted FIRST key must NEVER fall through
  // to a later key. Both `rule_id` and `rule_id_matched` are redacted together
  // on the agent path, but defend against any partial-redaction shape: if ANY
  // rule-id key is redacted, the whole entry collapses to the null/default-deny
  // bucket rather than resurfacing a sibling key's rule id (property #11).
  for (const key of RULE_ID_DETAIL_KEYS) {
    if (details[key] === REDACTED_SENTINEL) return null;
  }
  for (const key of RULE_ID_DETAIL_KEYS) {
    const value = details[key];
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }
  return null;
}

/**
 * Map the macOS extension's raw flow decision (`"allow" | "drop"`, see
 * castle-wall/ipc/messages.ts FlowDecisionNotification) to a category. The
 * extension path stores this string verbatim in `details.decision`.
 */
function categoryFromFlowDecision(
  decision: string
): FlowDecisionCategory | null {
  if (decision === "allow") return "allow";
  if (decision === "drop" || decision === "deny") return "deny";
  return null;
}

/**
 * Derive the decision category for a flow entry. Preference order:
 *   1. an explicit operator-decision `DecisionValue` (allow_once / deny_once / ...)
 *   2. the macOS extension's raw `"allow" | "drop"` flow decision
 *   3. the structural fallback from the stored `operation` tag
 * Each source agrees with the others by construction; the order just picks the
 * most specific evidence first. Returns null only when none is derivable (the
 * flow is then dropped, never guessed).
 */
function categoryOf(entry: AuditEntry): FlowDecisionCategory | null {
  const recorded = entry.details?.decision;
  if (typeof recorded === "string") {
    if (isDecisionValue(recorded)) return categoryFromDecisionValue(recorded);
    const flow = categoryFromFlowDecision(recorded);
    if (flow !== null) return flow;
  }
  return categoryFromOperation(entry.operation);
}

const DECISION_VALUES = new Set<string>([
  "allow_once",
  "allow_always",
  "deny_once",
  "deny_always",
  "timeout_default_deny",
]);

function isDecisionValue(value: string): value is DecisionValue {
  return DECISION_VALUES.has(value);
}

/** One attributed flow row in the read-out. */
export interface FlowAttribution {
  /** ISO timestamp the entry was recorded at. */
  timestamp: string;
  /** Stored operation tag (egress_allowed / egress_blocked / operator_decision). */
  operation: string;
  /** Coarse decision the flow resolved to. */
  decision: FlowDecisionCategory;
  /**
   * The rule id that decided this flow, or null when no rule matched (a baseline
   * default-deny). Operator-only; never surfaced to an agent-facing reader.
   */
  ruleId: string | null;
  /** Destination host, if the entry recorded one (operator legibility only). */
  destinationHost: string | null;
}

/** Per-rule rollup: counts + allow/deny/prompt split + a few sample flows. */
export interface PerRuleGroup {
  /** The matched rule id, or DEFAULT_DENY_BUCKET for the null-rule rollup. */
  ruleId: string;
  /** True iff this group is the synthetic default-deny (null rule) bucket. */
  isDefaultDeny: boolean;
  /** Total flows attributed to this rule. */
  total: number;
  /** Flows that resolved to allow. */
  allow: number;
  /** Flows that resolved to deny. */
  deny: number;
  /** Flows surfaced as a prompt (operator decision pending/recorded). */
  prompt: number;
  /** Up to `sampleLimit` representative flows (most recent first). */
  samples: FlowAttribution[];
}

/** Options for {@link groupFlowsByRule}. */
export interface GroupByRuleOptions {
  /** Max sample flows to retain per group. Default 3. */
  sampleLimit?: number;
}

const DEFAULT_SAMPLE_LIMIT = 3;

/**
 * Attribute every FLOW entry to its deciding rule and decision. Non-flow entries
 * (lifecycle events) are dropped. Entries whose decision cannot be derived are
 * dropped (never guessed). Order is preserved from the input.
 *
 * The caller is responsible for having pre-filtered to Castle Wall entries and
 * for the operator-context guarantee (these rows carry the unredacted rule id).
 */
export function attributeFlows(entries: AuditEntry[]): FlowAttribution[] {
  const flows: FlowAttribution[] = [];
  for (const entry of entries) {
    if (!FLOW_OPERATIONS.has(entry.operation)) continue;
    const decision = categoryOf(entry);
    if (decision === null) continue;
    flows.push({
      timestamp: entry.timestamp,
      operation: entry.operation,
      decision,
      ruleId: ruleIdOf(entry),
      destinationHost: destinationHostOf(entry),
    });
  }
  return flows;
}

/** Pull a destination host string from the stored entry, if present. */
function destinationHostOf(entry: AuditEntry): string | null {
  const dest = entry.details?.destination;
  if (dest && typeof dest === "object" && !Array.isArray(dest)) {
    const host = (dest as Record<string, unknown>).host;
    if (typeof host === "string" && host.length > 0) return host;
  }
  // macOS/unsigned path may also carry a flat dest_host in producer-signed bodies.
  const flat = entry.details?.dest_host;
  if (typeof flat === "string" && flat.length > 0) return flat;
  return null;
}

/**
 * Filter attributed flows to a single rule id. Pass `null` to select the
 * null-rule (default-deny) flows.
 *
 * SECURITY/correctness: the null-rule selector is `null`, NOT the
 * {@link DEFAULT_DENY_BUCKET} display label. The display label is a literal
 * string and may legitimately collide with an operator-authored rule id of the
 * same name; using it as a sentinel would make such a rule unselectable (it
 * would silently resolve to the default-deny flows instead). Matching here is on
 * the unaliased `ruleId` exactly, so a real rule named like the bucket label is
 * still reachable. (Mirrors the symbol-keyed null bucket in
 * {@link groupFlowsByRule}; the alias from the short `default-deny` token lives
 * in the CLI's `normalizeRuleFilter`, never in this core matcher.)
 */
export function filterFlowsByRule(
  flows: FlowAttribution[],
  ruleId: string | null
): FlowAttribution[] {
  if (ruleId === null) {
    return flows.filter((f) => f.ruleId === null);
  }
  return flows.filter((f) => f.ruleId === ruleId);
}

/**
 * Roll attributed flows up per deciding rule. Null-rule flows roll into the
 * synthetic {@link DEFAULT_DENY_BUCKET} group. Groups are returned sorted by
 * descending total (ties broken by ruleId for determinism), with the
 * default-deny bucket always sorted last so a real rule never sorts behind it on
 * a tie. Samples within each group are most-recent-first.
 */
export function groupFlowsByRule(
  flows: FlowAttribution[],
  options: GroupByRuleOptions = {}
): PerRuleGroup[] {
  const sampleLimit = options.sampleLimit ?? DEFAULT_SAMPLE_LIMIT;
  // Key the rollup on the REAL ruleId (a string) or a unique symbol for the
  // null-rule bucket — never on the DEFAULT_DENY_BUCKET display string. Keying
  // on the display label would merge a real rule literally authored with that
  // exact name into the synthetic default-deny bucket. A symbol can never equal
  // any operator-authored rule id (always a string), so the two never collide;
  // the display label is rendered only at group construction, below.
  const NULL_RULE_KEY = Symbol("default-deny");
  const byRule = new Map<string | symbol, PerRuleGroup>();

  for (const flow of flows) {
    const isDefaultDeny = flow.ruleId === null;
    const key: string | symbol = flow.ruleId ?? NULL_RULE_KEY;
    let group = byRule.get(key);
    if (!group) {
      group = {
        ruleId: isDefaultDeny ? DEFAULT_DENY_BUCKET : (flow.ruleId as string),
        isDefaultDeny,
        total: 0,
        allow: 0,
        deny: 0,
        prompt: 0,
        samples: [],
      };
      byRule.set(key, group);
    }
    group.total += 1;
    group[flow.decision] += 1;
    group.samples.push(flow);
  }

  // Most-recent-first samples, capped. Sort by timestamp desc then keep the head.
  for (const group of byRule.values()) {
    group.samples.sort((a, b) => (a.timestamp < b.timestamp ? 1 : a.timestamp > b.timestamp ? -1 : 0));
    group.samples = group.samples.slice(0, sampleLimit);
  }

  return [...byRule.values()].sort((a, b) => {
    // Default-deny bucket always last.
    if (a.isDefaultDeny !== b.isDefaultDeny) return a.isDefaultDeny ? 1 : -1;
    if (b.total !== a.total) return b.total - a.total;
    return a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0;
  });
}
