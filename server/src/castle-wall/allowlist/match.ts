/**
 * Allowlist rule matching -- the ONE destination/protocol matcher every
 * consumer shares.
 *
 * Extracted verbatim from `../egress-proxy.ts` (2026-07-14, observe-fold
 * idempotency chokepoint) so that BOTH the enforcing evaluator
 * (`egress-proxy.ts`, which re-exports this surface unchanged) and the
 * observe engine's allowlist-aware fold (`../observe/refresh.ts`) consult the
 * IDENTICAL matching semantics without the observe module ever importing the
 * evaluator module (THE RED-LINE structural pin in
 * `test/castle-wall/observe/red-line-invariant.test.ts`: the evaluator never
 * reads the candidate store, and observe/ never imports egress-proxy).
 * A second matcher implementation would drift; this file is the parity
 * chokepoint.
 *
 * Behavior contract: `canonicalizeConnectAuthority`, `ruleMatchesTarget`, and
 * `allowlistAllowsTarget` are byte-identical in behavior to their pre-move
 * `egress-proxy.ts` versions (existing egress-proxy tests pin them).
 * `ruleScopeCoversAgent` and `ruleProtocolMatches` are the two axes whose
 * semantics every shipped enforcer agrees on, exported for consumers (the
 * observe refresh) that reason about agent-attributed flows. NOTE the axes
 * the enforcers do NOT agree on: host_pattern syntax differs per enforcer
 * (the proxy/Swift honor `*.suffix`; the Rust daemon honors only
 * `.suffix`), and deny/allow precedence differs (daemon first-match-wins;
 * macOS deny-anywhere-wins; the proxy evaluates allow rules only) -- a
 * consumer needing a cross-enforcer "is this flow allowed" answer must not
 * reconstruct any single enforcer here (see
 * `observe/refresh.ts#candidateCurrentlyAllowed` for the conservative
 * intersection discipline).
 */

import net from "node:net";
import { domainToASCII } from "node:url";

import type { AllowlistRule, RuleProtocol, RuleScope } from "./schema.js";
import { ipMatches, cidrMatches } from "./ip-cidr.js";

export interface CanonicalConnectAuthority {
  host: string;
  port: number;
  authority: string;
  isIpLiteral: boolean;
}

export type CanonicalizationErrorCode =
  | "empty_authority"
  | "control_character"
  | "userinfo_forbidden"
  | "missing_port"
  | "invalid_port"
  | "invalid_host"
  | "bare_ipv6_literal";

export class ConnectAuthorityError extends Error {
  public readonly code: CanonicalizationErrorCode;

  constructor(code: CanonicalizationErrorCode) {
    super(code);
    this.name = "ConnectAuthorityError";
    this.code = code;
  }
}

export function canonicalizeConnectAuthority(input: string): CanonicalConnectAuthority {
  if (input.length === 0) {
    throw new ConnectAuthorityError("empty_authority");
  }
  if (/[\r\n\t]/u.test(input)) {
    throw new ConnectAuthorityError("control_character");
  }
  if (input.includes("@")) {
    throw new ConnectAuthorityError("userinfo_forbidden");
  }

  let host: string;
  let portText: string;
  if (input.startsWith("[")) {
    const close = input.indexOf("]");
    if (close < 0 || input.charAt(close + 1) !== ":") {
      throw new ConnectAuthorityError("missing_port");
    }
    host = input.slice(1, close);
    portText = input.slice(close + 2);
  } else {
    const lastColon = input.lastIndexOf(":");
    if (lastColon < 0) {
      throw new ConnectAuthorityError("missing_port");
    }
    host = input.slice(0, lastColon);
    portText = input.slice(lastColon + 1);
    if (host.includes(":")) {
      throw new ConnectAuthorityError("bare_ipv6_literal");
    }
  }

  const port = Number(portText);
  if (!/^[0-9]+$/u.test(portText) || !Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new ConnectAuthorityError("invalid_port");
  }

  host = host.trim();
  if (host.length === 0 || /[\r\n\t]/u.test(host) || host.includes("@")) {
    throw new ConnectAuthorityError("invalid_host");
  }

  const ipVersion = net.isIP(host);
  if (ipVersion !== 0) {
    const normalizedIp = ipVersion === 6 ? host.toLowerCase() : host;
    return {
      host: normalizedIp,
      port,
      authority: ipVersion === 6 ? `[${normalizedIp}]:${port}` : `${normalizedIp}:${port}`,
      isIpLiteral: true,
    };
  }

  const withoutTrailingDot = host.endsWith(".") ? host.slice(0, -1) : host;
  if (withoutTrailingDot.length === 0) {
    throw new ConnectAuthorityError("invalid_host");
  }
  const ascii = domainToASCII(withoutTrailingDot).toLowerCase();
  if (ascii.length === 0 || ascii.includes("[") || ascii.includes("]") || ascii.includes(":")) {
    throw new ConnectAuthorityError("invalid_host");
  }
  return {
    host: ascii,
    port,
    authority: `${ascii}:${port}`,
    isIpLiteral: false,
  };
}

/** Does the rule's protocol axis admit `protocol`? Absent = match any (only port/destination constrain). Identical semantics in every shipped enforcer (TS proxy, Rust daemon, Swift filter). */
export function ruleProtocolMatches(spec: RuleProtocol | undefined, protocol: "tcp" | "udp"): boolean {
  if (spec === undefined) return true;
  return spec === protocol || spec === "tcp+udp";
}

/**
 * Destination + port axes of a rule against a canonical target (protocol
 * deliberately excluded -- callers compose it via `ruleProtocolMatches`).
 * Destination axes compose as an OR (parity with the Swift evaluator): when
 * none is specified the destination is "match any" (only protocol/port
 * constrain); when any is specified, at least one must match. The ip/cidr
 * axes match `target.host` only when it is an IP literal (a DNS flow to a
 * resolver connects by raw IP), so a hostname target never spuriously matches.
 *
 */
function ruleMatchesDestination(rule: AllowlistRule, target: CanonicalConnectAuthority): boolean {
  if (rule.match.port !== undefined && !portMatches(rule.match.port, target.port)) {
    return false;
  }

  const hasHost = rule.match.host !== undefined;
  const hasHostPattern = rule.match.host_pattern !== undefined && rule.match.host_pattern.length > 0;
  const hasIp = rule.match.ip !== undefined;
  const hasCidr = rule.match.cidr !== undefined;
  if (!hasHost && !hasHostPattern && !hasIp && !hasCidr) {
    return true;
  }

  if (rule.match.host !== undefined && hostMatches(rule.match.host, target.host)) {
    return true;
  }
  if (rule.match.host_pattern !== undefined && rule.match.host_pattern.length > 0 && hostPatternMatches(rule.match.host_pattern, target.host)) {
    return true;
  }
  if (rule.match.ip !== undefined && ipMatches(rule.match.ip, target.host)) {
    return true;
  }
  if (rule.match.cidr !== undefined && cidrMatches(rule.match.cidr, target.host)) {
    return true;
  }
  return false;
}

/** The CONNECT proxy's per-rule check: tcp protocol semantics + destination/port. Byte-identical behavior to the pre-move `egress-proxy.ts` version. */
export function ruleMatchesTarget(rule: AllowlistRule, target: CanonicalConnectAuthority): boolean {
  return ruleProtocolMatches(rule.match.protocol, "tcp") && ruleMatchesDestination(rule, target);
}

/** Does any allow rule admit this tcp CONNECT target? The enforcing proxy/gate evaluator's exact check. */
export function allowlistAllowsTarget(rules: AllowlistRule[], target: CanonicalConnectAuthority): boolean {
  return rules.some((rule) => rule.disposition === "allow" && ruleMatchesTarget(rule, target));
}

/**
 * Does this rule's SCOPE apply to the given agent? Byte-for-byte parity with
 * the enforcing Rust daemon's `RuleScope::applies_to`
 * (castle-wall-daemon/src/policy.rs): an empty scope (no agent_ids and no
 * template_ids) applies to every wrapped agent; otherwise the agent matches
 * when EITHER its instance id is in agent_ids OR its template is in
 * template_ids. (NOTE: the in-process CONNECT proxy's `ruleMatchesTarget`
 * path deliberately does not evaluate scope -- the proxy has no per-flow
 * agent attribution; the daemon does, and any consumer reasoning about "is
 * this flow allowed for THIS agent" must use this check.)
 */
export function ruleScopeCoversAgent(
  scope: RuleScope,
  agent: { agent_id: string; agent_template: string },
): boolean {
  const scopedByAgent = (scope.agent_ids?.length ?? 0) > 0;
  const scopedByTemplate = (scope.template_ids?.length ?? 0) > 0;
  if (!scopedByAgent && !scopedByTemplate) return true;
  if (scopedByAgent && scope.agent_ids!.includes(agent.agent_id)) return true;
  if (scopedByTemplate && scope.template_ids!.includes(agent.agent_template)) return true;
  return false;
}


function portMatches(spec: number | number[], port: number): boolean {
  return Array.isArray(spec) ? spec.includes(port) : spec === port;
}

function hostMatches(spec: string | string[], host: string): boolean {
  const values = Array.isArray(spec) ? spec : [spec];
  return values.some((candidate) => canonicalizeRuleHost(candidate) === host);
}

function hostPatternMatches(pattern: string, host: string): boolean {
  if (pattern.startsWith("*.")) {
    const suffix = canonicalizeRuleHost(pattern.slice(2));
    return host.endsWith(`.${suffix}`) && host !== suffix;
  }
  return canonicalizeRuleHost(pattern) === host;
}

function canonicalizeRuleHost(host: string): string {
  const ipVersion = net.isIP(host);
  if (ipVersion !== 0) {
    return ipVersion === 6 ? host.toLowerCase() : host;
  }
  return canonicalizeConnectAuthority(`${host}:443`).host;
}
