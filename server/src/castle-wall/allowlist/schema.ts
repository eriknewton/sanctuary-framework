/**
 * Castle Wall allowlist rule schema.
 *
 * Each rule is one JSON document under `<fortress>/policy/egress/rules/<rule-id>.json`.
 * Rules describe a destination predicate, an agent-scope predicate, and a disposition.
 * The filter daemon evaluates an outbound flow against the loaded ruleset and emits
 * an EgressDecision (see decision/types.ts).
 *
 * Source: Castle Wall Phase 1 Scope Lock 2026-05-03 section 4 Option A recommendation.
 */

import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../constants.js";
import { isValidIp, isValidCidr } from "./ip-cidr.js";
import { validateRuleId } from "./rule-identity.js";

/** Protocol value for a rule's match clause. */
export type RuleProtocol = "tcp" | "udp" | "tcp+udp";

/** Disposition applied when a rule matches an outbound flow. */
export type RuleDisposition = "allow" | "prompt" | "deny";

/**
 * Time-of-day window where the rule is active. Times are HH:MM in the operator's
 * fortress-local timezone. Phase 1 supports same-day windows only (start before end).
 */
export interface RuleTimeWindow {
  start: string;
  end: string;
}

/**
 * Match conditions for a rule. At least one destination axis (host,
 * host_pattern, ip, or cidr) OR port MUST be specified at validation time. An
 * unspecified field is "match any."
 *
 * Destination axes compose as an OR: a rule that specifies more than one of
 * host / host_pattern / ip / cidr matches a flow when ANY of those axes match.
 *
 * `ip` matches a flow's resolved destination IP exactly (family-aware: an IPv4
 * literal never matches an IPv6 destination). `cidr` matches by family-aware
 * prefix containment. Both accept a single string or an array. These exist so a
 * DNS allow can be scoped to the system resolver set ONLY (see #380); the host
 * axis can never match a DNS flow because such flows carry no hostname.
 */
export interface RuleMatch {
  host?: string | string[];
  host_pattern?: string;
  ip?: string | string[];
  cidr?: string | string[];
  port?: number | number[];
  protocol?: RuleProtocol;
}

/**
 * Scope describes which wrapped agents the rule applies to. An empty agent_ids
 * AND empty template_ids AND empty uids all mean "all wrapped agents."
 *
 * `uids` (S5-0, 2026-07-14 two-confined-uid extension): scopes a rule to one
 * or more macOS real uids directly, composing as an OR with `agent_ids` /
 * `template_ids` (same as the destination-axis OR-composition on `RuleMatch`).
 * This is the axis a gate-scoped endpoint rule uses so it matches the
 * `sanctuary-gate` confined uid WITHOUT matching the wrapped agent's uid --
 * the Swift `AllowlistEvaluator.scopeMatches` compares against the flow's
 * `sourceRuid`. Any caller that composes/unions rule scopes (e.g.
 * `dns-derivation.ts`) must fold this axis in too, or a uid-scoped rule's
 * derived companion rule silently widens back to "all agents."
 */
export interface RuleScope {
  agent_ids?: string[];
  template_ids?: string[];
  uids?: number[];
}

/**
 * A single allowlist rule. The `id` is a stable, bounded ASCII identity used
 * for audit references and manifest entries; if you change a rule's effect,
 * mint a new id. It is not required to be a UUID.
 */
export interface AllowlistRule {
  id: string;
  schema_version: typeof CASTLE_WALL_SCHEMA_VERSION_V1;
  created_at: string;
  description?: string;
  match: RuleMatch;
  scope: RuleScope;
  disposition: RuleDisposition;
  time_window?: RuleTimeWindow;
  /**
   * True when this rule was auto-derived by the daemon rather than authored by
   * an operator (e.g. the scoped DNS allow derived from hostname rules, #380).
   * Surfaced as DERIVED in policy introspection so a derived grant is never
   * silently invisible. Omitted (not `false`) on operator-authored rules so
   * their canonical-JSON bytes are unchanged.
   */
  derived?: boolean;
}

/**
 * Validate a candidate rule. Returns an array of structural issues (empty
 * means valid). Cryptographic checks live in parse.ts; this is the schema
 * conformance gate that runs before signature verification.
 */
/**
 * Coerce a `string | string[]` match field (sourced from untrusted JSON) into a
 * string array for validation. Non-string members survive as-is so the
 * downstream `isValidIp`/`isValidCidr` check rejects them.
 */
function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isValidPortNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= 65535;
}

/**
 * True when `value` is a positive integer uid within the `UInt32` wire range.
 * 0/root is never a valid scope member, and the sysext decodes `scope.uids`
 * as `[UInt32]` (castle-wall-macos `ManifestRuleScope`), so a value above
 * `UInt32.max` (LOW-1, 2026-07-14) passes canonical signing but fails Swift
 * decode -- an unappliable signed manifest. Cap it here at publish.
 */
function isPositiveUid(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isInteger(value) &&
    value >= 1 &&
    value <= 0xffffffff
  );
}

/**
 * Validate a `T | T[]` axis: present means a single valid scalar or a
 * NON-EMPTY array of valid scalars. `null`, wrong-typed scalars, empty
 * arrays, and wrong-typed array members all reject. This is load-bearing
 * cross-language parity (codex round-6): the Rust daemon's serde layer
 * refuses wrong-typed values outright, and reads an explicit JSON `null` as
 * "axis absent" — so a TS-side validator that accepted `host: null` by mere
 * key presence would sign a rule one side reads as constrained and the other
 * as any-destination. The validator must reject everything serde would
 * refuse or reinterpret.
 */
function validateAxisValues(
  axis: string,
  value: unknown,
  isValid: (entry: unknown) => boolean,
  expected: string,
  issues: string[],
): void {
  if (Array.isArray(value) && value.length === 0) {
    issues.push(`${axis} must not be an empty array (omit the axis instead)`);
    return;
  }
  const entries = Array.isArray(value) ? value : [value];
  for (const entry of entries) {
    if (!isValid(entry)) {
      issues.push(`${axis} contains invalid entry (expected ${expected}): ${String(entry)}`);
    }
  }
}

const KNOWN_RULE_KEYS = new Set([
  "id",
  "schema_version",
  "created_at",
  "description",
  "match",
  "scope",
  "disposition",
  "time_window",
  "derived",
]);
const KNOWN_MATCH_KEYS = new Set(["host", "host_pattern", "ip", "cidr", "port", "protocol"]);
const KNOWN_SCOPE_KEYS = new Set(["agent_ids", "template_ids", "uids"]);
const KNOWN_TIME_WINDOW_KEYS = new Set(["start", "end"]);

/**
 * Reject unknown fields, mirroring the Rust daemon's
 * `#[serde(deny_unknown_fields)]` on AllowlistRule / RuleMatch / RuleScope:
 * an unmodeled field can only come from a newer (or non-conforming) schema,
 * and the enforcing daemon will refuse the manifest — so the build-time
 * validator must refuse it FIRST, before it gets signed.
 */
function rejectUnknownKeys(
  label: string,
  value: object,
  known: Set<string>,
  issues: string[],
): void {
  for (const key of Object.keys(value)) {
    if (!known.has(key)) {
      issues.push(
        `${label} has unknown field "${key}" (fail closed: the enforcing daemons reject unmodeled fields)`
      );
    }
  }
}

export function validateRule(rule: AllowlistRule): string[] {
  const issues: string[] = [];
  const ruleIdIssue = validateRuleId(rule.id);
  if (ruleIdIssue !== null) issues.push(ruleIdIssue);
  if (rule.schema_version !== CASTLE_WALL_SCHEMA_VERSION_V1) {
    issues.push(
      `rule.schema_version unsupported (expected ${CASTLE_WALL_SCHEMA_VERSION_V1}, got ${String(rule.schema_version)})`
    );
  }
  if (!rule.created_at || typeof rule.created_at !== "string") {
    issues.push("rule.created_at missing or not a string");
  }
  if (rule.description !== undefined && typeof rule.description !== "string") {
    issues.push("rule.description must be a string when present");
  }
  if (rule.derived !== undefined && typeof rule.derived !== "boolean") {
    issues.push("rule.derived must be a boolean when present");
  }
  if (rule.time_window !== undefined) {
    const tw = rule.time_window;
    if (!tw || typeof tw !== "object" || Array.isArray(tw)) {
      issues.push("rule.time_window must be an object when present");
    } else {
      rejectUnknownKeys("rule.time_window", tw, KNOWN_TIME_WINDOW_KEYS, issues);
      if (!isNonEmptyString(tw.start) || !isNonEmptyString(tw.end)) {
        issues.push("rule.time_window.start/end must be non-empty strings");
      }
    }
  }
  rejectUnknownKeys("rule", rule, KNOWN_RULE_KEYS, issues);
  // Array.isArray guards (codex round-7): a JSON array satisfies
  // `typeof x === "object"`, but Rust serde refuses an array where a struct
  // is expected — so `match: []` / `scope: []` must be TS-invalid too.
  if (!rule.match || typeof rule.match !== "object" || Array.isArray(rule.match)) {
    issues.push("rule.match missing or not an object");
  } else {
    rejectUnknownKeys("rule.match", rule.match, KNOWN_MATCH_KEYS, issues);
    const hasHost = rule.match.host !== undefined;
    const hasHostPattern = rule.match.host_pattern !== undefined;
    const hasIp = rule.match.ip !== undefined;
    const hasCidr = rule.match.cidr !== undefined;
    const hasPort = rule.match.port !== undefined;
    if (!hasHost && !hasHostPattern && !hasIp && !hasCidr && !hasPort) {
      issues.push(
        "rule.match must specify at least one of host, host_pattern, ip, cidr, or port"
      );
    }
    if (hasHost) {
      validateAxisValues(
        "rule.match.host",
        rule.match.host,
        isNonEmptyString,
        "non-empty string",
        issues,
      );
    }
    if (hasHostPattern && !isNonEmptyString(rule.match.host_pattern)) {
      issues.push("rule.match.host_pattern must be a non-empty string");
    }
    // Fail closed on malformed IP/CIDR: a rule that cannot be matched safely
    // must be rejected at build time, never silently dropped (which would leave
    // an unintended any-destination grant) or shipped to the evaluator.
    if (hasIp) {
      validateAxisValues("rule.match.ip", rule.match.ip, isValidIp, "IP literal", issues);
    }
    if (hasCidr) {
      validateAxisValues(
        "rule.match.cidr",
        rule.match.cidr,
        (v) => typeof v === "string" && isValidCidr(v),
        "CIDR",
        issues,
      );
    }
    if (hasPort) {
      validateAxisValues(
        "rule.match.port",
        rule.match.port,
        isValidPortNumber,
        "integer in [1, 65535]",
        issues,
      );
    }
    if (rule.match.protocol !== undefined) {
      const p = rule.match.protocol;
      if (p !== "tcp" && p !== "udp" && p !== "tcp+udp") {
        issues.push(`rule.match.protocol must be tcp, udp, or tcp+udp (got ${String(p)})`);
      }
    }
  }
  if (!rule.scope || typeof rule.scope !== "object" || Array.isArray(rule.scope)) {
    issues.push("rule.scope missing or not an object");
  } else {
    rejectUnknownKeys("rule.scope", rule.scope, KNOWN_SCOPE_KEYS, issues);
    for (const key of ["agent_ids", "template_ids"] as const) {
      const ids = rule.scope[key];
      if (ids === undefined) continue;
      if (!Array.isArray(ids) || ids.some((id) => !isNonEmptyString(id))) {
        issues.push(`rule.scope.${key} must be an array of non-empty strings when present`);
      }
    }
    if (rule.scope.uids !== undefined) {
      if (!Array.isArray(rule.scope.uids) || rule.scope.uids.some((uid) => !isPositiveUid(uid))) {
        issues.push("rule.scope.uids must be an array of positive integers when present");
      }
    }
  }
  if (rule.disposition !== "allow" && rule.disposition !== "prompt" && rule.disposition !== "deny") {
    issues.push(`rule.disposition must be allow, prompt, or deny (got ${String(rule.disposition)})`);
  }
  return issues;
}
