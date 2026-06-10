/**
 * Auto-derivation of a scoped DNS allow-rule for hostname rules (#380).
 *
 * Problem: a hostname allow-rule can never match a DNS flow (DNS flows carry no
 * hostname), so an operator who allows `api.example.com` must ALSO add a
 * companion `port: 53` rule for the agent to resolve that name. But a bare
 * `port: 53` rule is any-resolver — it permits port 53 to ANY IP, which is a
 * DNS-tunneling exfil channel.
 *
 * Fix: when at least one hostname allow-rule exists, the daemon auto-derives a
 * single DNS allow scoped to the system-configured resolvers ONLY, via the
 * IP/CIDR matcher. The derived rule matches `destination ∈ {resolver IPs} AND
 * port 53`; a port-53 flow to a non-resolver IP does NOT match it.
 *
 * Security invariants (tested):
 *   - No hostname allow-rule => no derived rule (no standing port-53 grant).
 *   - The derived rule scopes to the resolver set only (never any-resolver).
 *   - When the resolver set cannot be determined, NO rule is emitted (fail
 *     closed: deny DNS rather than fall back to an any-resolver grant).
 *
 * This module is pure (resolvers are passed in) so it is unit-testable without
 * touching the host's real resolver configuration. The daemon supplies
 * `dns.getServers()` (verified to match `scutil --dns` nameservers on macOS).
 */

import type { AllowlistRule, RuleScope } from "./schema.js";
import { isValidIp } from "./ip-cidr.js";
import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../constants.js";

/** Stable id for the auto-derived scoped DNS rule. */
export const DERIVED_DNS_RULE_ID = "derived_dns_for_hostname_rules";

/**
 * Normalize a raw resolver list (as returned by `dns.getServers()`) to a
 * deduped array of bare IP literals. `getServers()` may return RFC-5952 forms
 * with a custom port (`8.8.8.8:1053`, `[2001:db8::1]:1053`) and IPv6 link-local
 * addresses with a zone id (`fe80::1%en0`); we strip the port and zone, keep
 * the address, and drop anything that is not a valid IP.
 */
export function normalizeResolvers(servers: readonly unknown[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of servers) {
    if (typeof raw !== "string") continue;
    let addr = raw.trim();
    if (addr.startsWith("[")) {
      // Bracketed IPv6, optionally with `:port` after the closing bracket.
      const close = addr.indexOf("]");
      if (close > 0) addr = addr.slice(1, close);
    } else if ((addr.match(/:/g) ?? []).length === 1) {
      // Exactly one colon => IPv4 with a `:port` suffix; bare IPv6 has many.
      addr = addr.slice(0, addr.indexOf(":"));
    }
    const zone = addr.indexOf("%");
    if (zone >= 0) addr = addr.slice(0, zone);
    if (!isValidIp(addr)) continue;
    if (seen.has(addr)) continue;
    seen.add(addr);
    out.push(addr);
  }
  return out;
}

/** True iff a scope means "all wrapped agents" (no agent_ids and no template_ids). */
function scopeIsAll(scope: RuleScope): boolean {
  const hasAgents = (scope.agent_ids?.length ?? 0) > 0;
  const hasTemplates = (scope.template_ids?.length ?? 0) > 0;
  return !hasAgents && !hasTemplates;
}

/**
 * The derived DNS rule must apply to exactly the agents that hold a hostname
 * rule. If ANY parent hostname rule is unscoped (all agents), the derived rule
 * is unscoped too (those agents all need to resolve). Otherwise the derived
 * scope is the union of the parents' agent_ids / template_ids.
 */
function unionScope(scopes: readonly RuleScope[]): RuleScope {
  if (scopes.some(scopeIsAll)) return {};
  const agentIds = new Set<string>();
  const templateIds = new Set<string>();
  for (const scope of scopes) {
    for (const id of scope.agent_ids ?? []) agentIds.add(id);
    for (const id of scope.template_ids ?? []) templateIds.add(id);
  }
  const result: RuleScope = {};
  if (agentIds.size > 0) result.agent_ids = [...agentIds].sort();
  if (templateIds.size > 0) result.template_ids = [...templateIds].sort();
  return result;
}

/** Inputs to {@link deriveDnsRuleForHostnameRules}. */
export interface DeriveDnsRuleInput {
  /** The operator-authored rule set (read from disk). */
  rules: readonly AllowlistRule[];
  /** The system resolver set, typically `dns.getServers()`. */
  resolvers: readonly unknown[];
  /** ISO timestamp stamped onto the derived rule's `created_at`. */
  createdAt: string;
}

/**
 * Derive the scoped DNS allow-rule, or return null when one should not exist:
 *   - no hostname allow-rule present (no standing port-53 grant), or
 *   - the resolver set normalizes to empty (fail closed: deny DNS rather than
 *     emit an any-resolver grant), or
 *   - an operator-authored rule already claims the reserved derived id (the
 *     operator override wins; we never emit a duplicate id).
 */
export function deriveDnsRuleForHostnameRules(
  input: DeriveDnsRuleInput
): AllowlistRule | null {
  if (input.rules.some((rule) => rule.id === DERIVED_DNS_RULE_ID)) {
    return null;
  }
  const hostnameRules = input.rules.filter(
    (rule) =>
      rule.disposition === "allow" &&
      (rule.match.host !== undefined || rule.match.host_pattern !== undefined)
  );
  if (hostnameRules.length === 0) return null;

  const resolvers = normalizeResolvers(input.resolvers);
  if (resolvers.length === 0) return null;

  return {
    id: DERIVED_DNS_RULE_ID,
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    created_at: input.createdAt,
    description:
      "Auto-derived scoped DNS allow (#380): port 53, system resolvers only " +
      "(tcp+udp). Lets agents holding a hostname allow-rule resolve names " +
      "without an any-resolver port-53 grant. Scoped to the resolver set; a " +
      "port-53 flow to a non-resolver IP does not match.",
    match: { ip: resolvers, port: [53], protocol: "tcp+udp" },
    scope: unionScope(hostnameRules.map((rule) => rule.scope)),
    disposition: "allow",
    derived: true,
  };
}
