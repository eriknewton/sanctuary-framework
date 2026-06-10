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
 * AND empty template_ids both mean "all wrapped agents."
 */
export interface RuleScope {
  agent_ids?: string[];
  template_ids?: string[];
}

/**
 * A single allowlist rule. The `id` is a stable UUID used for audit references
 * and manifest entries; if you change a rule's effect, mint a new id.
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
function toStringArray(value: unknown): string[] {
  if (Array.isArray(value)) return value as string[];
  return [value as string];
}

export function validateRule(rule: AllowlistRule): string[] {
  const issues: string[] = [];
  if (!rule.id || typeof rule.id !== "string") {
    issues.push("rule.id missing or not a string");
  }
  if (rule.schema_version !== CASTLE_WALL_SCHEMA_VERSION_V1) {
    issues.push(
      `rule.schema_version unsupported (expected ${CASTLE_WALL_SCHEMA_VERSION_V1}, got ${String(rule.schema_version)})`
    );
  }
  if (!rule.created_at || typeof rule.created_at !== "string") {
    issues.push("rule.created_at missing or not a string");
  }
  if (!rule.match || typeof rule.match !== "object") {
    issues.push("rule.match missing");
  } else {
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
    // Fail closed on malformed IP/CIDR: a rule that cannot be matched safely
    // must be rejected at build time, never silently dropped (which would leave
    // an unintended any-destination grant) or shipped to the evaluator.
    if (hasIp) {
      for (const value of toStringArray(rule.match.ip)) {
        if (!isValidIp(value)) {
          issues.push(`rule.match.ip contains invalid IP literal: ${String(value)}`);
        }
      }
    }
    if (hasCidr) {
      for (const value of toStringArray(rule.match.cidr)) {
        if (!isValidCidr(value)) {
          issues.push(`rule.match.cidr contains invalid CIDR: ${String(value)}`);
        }
      }
    }
  }
  if (!rule.scope || typeof rule.scope !== "object") {
    issues.push("rule.scope missing");
  }
  if (rule.disposition !== "allow" && rule.disposition !== "prompt" && rule.disposition !== "deny") {
    issues.push(`rule.disposition must be allow, prompt, or deny (got ${String(rule.disposition)})`);
  }
  return issues;
}
