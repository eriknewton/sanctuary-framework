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
 * Match conditions for a rule. At least one of host, host_pattern, or port MUST
 * be specified at validation time. An unspecified field is "match any."
 */
export interface RuleMatch {
  host?: string | string[];
  host_pattern?: string;
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
}

/**
 * Validate a candidate rule. Returns an array of structural issues (empty
 * means valid). Cryptographic checks live in parse.ts; this is the schema
 * conformance gate that runs before signature verification.
 */
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
    const hasPort = rule.match.port !== undefined;
    if (!hasHost && !hasHostPattern && !hasPort) {
      issues.push("rule.match must specify at least one of host, host_pattern, or port");
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
