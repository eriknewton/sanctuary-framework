/**
 * HABEAS PORT — reserved guaranteed-egress distress lane (agent-side
 * sovereignty foundation, ratified 2026-06-12).
 *
 * A wrapped agent must always retain one narrow, audited lane through which it
 * can signal "I am in distress" to its operator — no matter how restrictive
 * the operator's egress policy is. This module derives the reserved allow
 * rule(s) for that lane during manifest composition and REJECTS (fail closed)
 * any operator-authored ruleset that tries to claim, remove, or shadow it.
 *
 * What the lane is NOT: a data channel. The rules below admit only
 *   - loopback traffic to the fixed habeas distress port (the local operator
 *     notification surface), and
 *   - when the operator has configured a distress webhook, TCP to exactly
 *     that webhook's host:port.
 * The payload that travels over the lane is separately bounded and audited by
 * the distress emission surface (src/distress/), which never carries state
 * content. Guaranteed egress here means "the distress signal cannot be
 * silenced by policy", not "the agent gets a free network hole".
 *
 * Enforcement layers:
 *   - Server-side (this module): derivation always injects the rules; a
 *     conflicting operator ruleset aborts manifest composition with a clear
 *     error instead of building a wall that could silence distress.
 *   - Extension-side (DEFERRED to the next sysext window): the Swift/Rust
 *     evaluators must give the reserved rule ids non-shadowable precedence so
 *     a stale or hand-edited on-disk ruleset can never out-rank them.
 */

import type { AllowlistRule, RuleScope } from "./schema.js";
import { ipMatches, cidrMatches } from "./ip-cidr.js";
import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../constants.js";
import {
  deriveDnsRuleForHostnameRules,
} from "./dns-derivation.js";
import {
  DERIVED_GATE_RULE_ID,
  deriveGateAllowRule,
  type ExclusiveEgressGatePolicy,
} from "./gate-derivation.js";

/**
 * Every reserved habeas rule id starts with this prefix. Operator-authored
 * rules may never claim it (checked in {@link findHabeasConflicts}).
 */
export const HABEAS_RULE_ID_PREFIX = "reserved_habeas_distress";

/** Id of the always-present loopback distress rule. */
export const HABEAS_LOCAL_RULE_ID = "reserved_habeas_distress_local";

/** Id of the optional operator-configured distress webhook rule. */
export const HABEAS_WEBHOOK_RULE_ID = "reserved_habeas_distress_webhook";

/**
 * The habeas distress port. A fixed, unprivileged port reserved for the local
 * distress lane: the loopback allow-rule admits TCP to this port on
 * 127.0.0.1/::1 only. Chosen from the unassigned dynamic-adjacent range; the
 * exact number is arbitrary but MUST stay stable — the extension-side
 * precedence work (deferred) keys on the rule ids and this port.
 */
export const HABEAS_DISTRESS_PORT = 8741;

/** Loopback literals the local rule admits. */
export const HABEAS_LOOPBACK_IPS = ["127.0.0.1", "::1"] as const;

/**
 * Reserved synthetic agent id the habeas rules are scoped to. CRITICAL
 * anti-exfiltration property (codex round-1 findings 1+2): the distress
 * signal is emitted by the SANCTUARY SERVER process (the MCP tool runs
 * server-side), never by a wrapped agent making raw TCP connections. Scoping
 * the reserved allow-rules to this synthetic id — which no wrapped agent is
 * ever assigned — means NO agent-classified flow matches them, so the lane
 * grants zero raw-socket bandwidth to agents (no unaudited bytes to a local
 * 8741 listener, no arbitrary HTTPS to the webhook host). The enforcing
 * extension attributes the daemon's own distress delivery flows to this id
 * (sysext work, deferred); until that lands, an armed default-deny wall may
 * block the webhook POST itself — which is safe: webhook failure is audited
 * and non-fatal, and the local lane (audit + operator notification) is
 * in-process and untouchable by the network plane.
 */
export const HABEAS_EMITTER_AGENT_ID = "sanctuary:habeas-distress-emitter";

/** The distress webhook destination, already validated by the config loader. */
export interface HabeasWebhookTarget {
  /** Hostname or IP literal of the operator's distress webhook. */
  host: string;
  /** TCP port of the webhook (scheme default applied by the parser). */
  port: number;
}

/**
 * Parse a distress webhook URL into the host/port pair the allow-rule needs.
 * Returns null for anything that is not a well-formed http(s) URL — the
 * caller treats null as "no webhook lane" (the local lane still always
 * exists). Only http/https are accepted: the lane is a narrow signal channel,
 * not a general transport.
 */
export function parseHabeasWebhookTarget(url: string): HabeasWebhookTarget | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return null;
  const host = parsed.hostname.replace(/^\[|\]$/g, "");
  if (host.length === 0) return null;
  const port = parsed.port !== ""
    ? Number(parsed.port)
    : parsed.protocol === "https:" ? 443 : 80;
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { host, port };
}

/**
 * Scope applied to every derived habeas rule: the reserved emitter id only.
 * Never `{}` (all agents) — see HABEAS_EMITTER_AGENT_ID.
 */
const HABEAS_EMITTER_SCOPE: RuleScope = { agent_ids: [HABEAS_EMITTER_AGENT_ID] };

/**
 * Derive the reserved habeas distress rules. The loopback rule is ALWAYS
 * present; the webhook rule is present exactly when the operator configured a
 * distress webhook. Both are stamped `derived: true` so policy introspection
 * shows them as DERIVED rather than silently invisible.
 */
export function deriveHabeasDistressRules(input: {
  webhook?: HabeasWebhookTarget | undefined;
  createdAt: string;
}): AllowlistRule[] {
  const rules: AllowlistRule[] = [
    {
      id: HABEAS_LOCAL_RULE_ID,
      schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
      created_at: input.createdAt,
      description:
        "HABEAS PORT (reserved): guaranteed local distress lane. Loopback " +
        `TCP to port ${HABEAS_DISTRESS_PORT} only. Always present; operator ` +
        "policy cannot remove or shadow it. Carries bounded distress " +
        "signals, never state content.",
      match: {
        ip: [...HABEAS_LOOPBACK_IPS],
        port: [HABEAS_DISTRESS_PORT],
        protocol: "tcp",
      },
      scope: { ...HABEAS_EMITTER_SCOPE },
      disposition: "allow",
      derived: true,
    },
  ];
  if (input.webhook !== undefined) {
    rules.push({
      id: HABEAS_WEBHOOK_RULE_ID,
      schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
      created_at: input.createdAt,
      description:
        "HABEAS PORT (reserved): operator-configured distress webhook lane. " +
        `TCP to ${input.webhook.host}:${input.webhook.port} only. Carries ` +
        "HMAC-signed bounded distress signals, never state content.",
      match: {
        host: [input.webhook.host],
        port: [input.webhook.port],
        protocol: "tcp",
      },
      scope: { ...HABEAS_EMITTER_SCOPE },
      disposition: "allow",
      derived: true,
    });
  }
  return rules;
}

function toArray<T>(value: T | T[] | undefined): T[] {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

function portsCover(spec: number | number[] | undefined, port: number): boolean {
  // An unspecified port axis is "match any" — it covers every port.
  if (spec === undefined) return true;
  return toArray(spec).includes(port);
}

function hostEquals(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}

function hostPatternCovers(pattern: string, host: string): boolean {
  const lower = host.toLowerCase();
  // `*.suffix` form (allowlist/gate spelling).
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(2).toLowerCase();
    return lower.endsWith(`.${suffix}`) && lower !== suffix;
  }
  // `.suffix` form (the Linux kernel evaluator's suffix-glob spelling). The
  // gate must reject a deny rule that the enforcing evaluator would actually
  // match against the lane, regardless of which suffix spelling the operator
  // used (cross-language parity with the Rust gate; codex round-2 HIGH).
  if (pattern.startsWith(".")) {
    const patternLower = pattern.toLowerCase();
    return lower.endsWith(patternLower) && lower.length > patternLower.length;
  }
  return hostEquals(pattern, host);
}

/**
 * True when a deny/prompt rule's destination axes could cover `host:port`.
 * Conservative: an absent destination axis set means "any destination".
 */
function ruleCoversHostTarget(rule: AllowlistRule, host: string, port: number): boolean {
  if (!portsCover(rule.match.port, port)) return false;
  const hasHost = rule.match.host !== undefined;
  const hasHostPattern = rule.match.host_pattern !== undefined;
  const hasIp = rule.match.ip !== undefined;
  const hasCidr = rule.match.cidr !== undefined;
  if (!hasHost && !hasHostPattern && !hasIp && !hasCidr) return true;
  if (hasHost && toArray(rule.match.host).some((h) => hostEquals(h, host))) return true;
  if (
    hasHostPattern &&
    typeof rule.match.host_pattern === "string" &&
    hostPatternCovers(rule.match.host_pattern, host)
  ) {
    return true;
  }
  // ip/cidr axes can cover the webhook target when it is an IP literal.
  if (hasIp && rule.match.ip !== undefined && ipMatches(rule.match.ip, host)) return true;
  if (hasCidr && rule.match.cidr !== undefined && cidrMatches(rule.match.cidr, host)) return true;
  return false;
}

/** True when a deny/prompt rule could cover loopback traffic to the habeas port. */
function ruleCoversLoopbackLane(rule: AllowlistRule): boolean {
  if (!portsCover(rule.match.port, HABEAS_DISTRESS_PORT)) return false;
  const hasHost = rule.match.host !== undefined;
  const hasHostPattern = rule.match.host_pattern !== undefined;
  const hasIp = rule.match.ip !== undefined;
  const hasCidr = rule.match.cidr !== undefined;
  if (!hasHost && !hasHostPattern && !hasIp && !hasCidr) return true;
  for (const loopback of HABEAS_LOOPBACK_IPS) {
    if (hasIp && rule.match.ip !== undefined && ipMatches(rule.match.ip, loopback)) return true;
    if (hasCidr && rule.match.cidr !== undefined && cidrMatches(rule.match.cidr, loopback)) {
      return true;
    }
    if (hasHost && toArray(rule.match.host).some((h) => hostEquals(h, loopback))) return true;
  }
  return false;
}

/**
 * Scan an operator-authored ruleset for anything that conflicts with the
 * habeas lane. Returns human-readable issues (empty = clean). Conflicts:
 *
 *   1. A rule claiming a reserved habeas id (or the reserved prefix) — an
 *      operator rule could otherwise replace the lane with a deny.
 *   2. A deny/prompt rule whose match could cover the loopback lane
 *      (loopback IPs at the habeas port, or an any-destination port match
 *      that includes it).
 *   3. When a distress webhook is configured: a deny/prompt rule whose match
 *      could cover the webhook host:port.
 *
 * The check is deliberately conservative (axis-level coverage, not full
 * evaluator semantics): a rule that MIGHT shadow the lane is rejected with a
 * clear error so the operator can scope it down, rather than building a wall
 * that might silence distress. Authoritative non-shadowability inside the
 * enforcing extension is deferred to the next sysext window.
 */
export function findHabeasConflicts(
  rules: readonly AllowlistRule[],
  webhook?: HabeasWebhookTarget,
): string[] {
  const issues: string[] = [];
  for (const rule of rules) {
    if (typeof rule.id === "string" && rule.id.startsWith(HABEAS_RULE_ID_PREFIX)) {
      issues.push(
        `rule "${rule.id}" claims the reserved habeas distress id prefix ` +
          `"${HABEAS_RULE_ID_PREFIX}"; reserved rules are derived, never authored`,
      );
      continue;
    }
    if (rule.disposition !== "deny" && rule.disposition !== "prompt") continue;
    if (ruleCoversLoopbackLane(rule)) {
      issues.push(
        `rule "${rule.id}" (${rule.disposition}) could shadow the reserved habeas ` +
          `distress lane (loopback port ${HABEAS_DISTRESS_PORT}); scope it to exclude ` +
          "loopback or the habeas port",
      );
      continue;
    }
    if (webhook !== undefined && ruleCoversHostTarget(rule, webhook.host, webhook.port)) {
      issues.push(
        `rule "${rule.id}" (${rule.disposition}) could shadow the configured distress ` +
          `webhook lane (${webhook.host}:${webhook.port}); scope it to exclude the ` +
          "distress webhook destination",
      );
    }
  }
  return issues;
}

/**
 * True iff `rule` is a GENUINE derived reserved habeas rule, validated by
 * EXACT shape — never by trusting the `derived` flag. Parity mirror of the
 * Rust `is_derived_habeas_rule` (castle-wall-daemon/src/habeas.rs), kept in
 * lockstep via the shared fixture's `composed_cases`:
 *
 *   local:   ip exactly ["127.0.0.1", "::1"], port exactly [8741],
 *            protocol tcp, NO host/host_pattern/cidr axes, no time_window,
 *            emitter-only scope, allow.
 *   webhook: exactly one host, exactly one port, protocol tcp, NO
 *            ip/cidr/host_pattern axes, no time_window, emitter-only scope,
 *            allow.
 */
export function isGenuineDerivedHabeasRule(rule: AllowlistRule): boolean {
  if (rule.disposition !== "allow") return false;
  if (rule.time_window !== undefined) return false;
  const scope = rule.scope ?? {};
  const emitterScoped =
    Array.isArray(scope.agent_ids) &&
    scope.agent_ids.length === 1 &&
    scope.agent_ids[0] === HABEAS_EMITTER_AGENT_ID &&
    (scope.template_ids === undefined || scope.template_ids.length === 0) &&
    // S5-0 (2026-07-14): `uids` composes as an OR with agent_ids/template_ids
    // (dns-derivation.ts, AllowlistEvaluator.scopeMatches), so a rule
    // claiming the reserved id PLUS a non-empty `uids` axis would ALSO match
    // extra uid-scoped flows beyond the genuine emitter-only grant -- exactly
    // the kind of widened-but-still-"genuine"-looking shape this exact-match
    // recognizer exists to catch. The Rust daemon's `deny_unknown_fields` on
    // `RuleScope` independently rejects any `uids`-bearing rule file at parse
    // time (it does not model this field), so this branch is TS/Swift-only
    // defense in depth, not a parity gap.
    (scope.uids === undefined || scope.uids.length === 0);
  if (!emitterScoped) return false;
  const m = rule.match;
  const protocolIsTcp =
    typeof m.protocol === "string" && m.protocol.toLowerCase() === "tcp";

  // Scalar tolerance: the schema types list axes as `T | T[]`, and the Rust
  // daemon normalizes a scalar to a one-element list at parse time — so the
  // shape comparison here must see the normalized (array) view too, or the
  // two recognizers would disagree on a scalar-form reserved rule.
  if (rule.id === HABEAS_LOCAL_RULE_ID) {
    const ip = m.ip === undefined ? [] : toArray(m.ip);
    const ipOk =
      ip.length === 2 &&
      ip[0] === HABEAS_LOOPBACK_IPS[0] &&
      ip[1] === HABEAS_LOOPBACK_IPS[1];
    const port = m.port === undefined ? [] : toArray(m.port);
    const portOk = port.length === 1 && port[0] === HABEAS_DISTRESS_PORT;
    return (
      ipOk &&
      portOk &&
      protocolIsTcp &&
      m.host === undefined &&
      m.host_pattern === undefined &&
      m.cidr === undefined
    );
  }

  if (rule.id === HABEAS_WEBHOOK_RULE_ID) {
    const hostOk = m.host !== undefined && toArray(m.host).length === 1;
    const portOk = m.port !== undefined && toArray(m.port).length === 1;
    return (
      hostOk &&
      portOk &&
      protocolIsTcp &&
      m.host_pattern === undefined &&
      m.ip === undefined &&
      m.cidr === undefined
    );
  }

  return false;
}

/**
 * Run the conflict gate over an already-COMPOSED manifest's rules. Parity
 * mirror of the Rust `find_habeas_conflicts_in_composed`
 * (castle-wall-daemon/src/habeas.rs), asserted from both languages via the
 * shared fixture's `composed_cases` — so the TS and Linux gates accept and
 * reject identical composed manifests.
 *
 * Structural invariants, then the operator-remainder scan:
 *   - Any rule carrying a reserved id that is NOT a genuine derived rule
 *     (exact shape, see {@link isGenuineDerivedHabeasRule}) is rejected.
 *   - EXACTLY one genuine local reserved rule in EVERY manifest: the composer
 *     ({@link composeEffectiveRules}) always injects the lane, so a composed
 *     manifest without it is stale, hand-edited, or produced by a
 *     non-conforming toolchain. No legacy allowance — there is no manifest
 *     version field that could prove pre-habeas provenance.
 *   - At most ONE genuine webhook reserved rule (a duplicate could redefine
 *     the protected webhook target).
 *   - The (provably unique, provably genuine) derived rules are exempted, the
 *     webhook target is recovered from the genuine webhook rule, and the
 *     operator remainder is scanned with {@link findHabeasConflicts}.
 */
export function findHabeasConflictsInComposed(
  rules: readonly AllowlistRule[],
): string[] {
  const issues: string[] = [];
  let localCount = 0;
  let webhookCount = 0;
  for (const rule of rules) {
    if (typeof rule.id !== "string" || !rule.id.startsWith(HABEAS_RULE_ID_PREFIX)) {
      continue;
    }
    if (!isGenuineDerivedHabeasRule(rule)) {
      issues.push(
        `rule "${rule.id}" claims the reserved habeas distress id prefix ` +
          `"${HABEAS_RULE_ID_PREFIX}" but is not a genuine derived reserved ` +
          "rule; reserved rules are derived, never authored",
      );
      continue;
    }
    if (rule.id === HABEAS_LOCAL_RULE_ID) localCount += 1;
    else if (rule.id === HABEAS_WEBHOOK_RULE_ID) webhookCount += 1;
  }
  if (localCount !== 1) {
    issues.push(
      `manifest has ${localCount} genuine "${HABEAS_LOCAL_RULE_ID}" rules; ` +
        "exactly one must be present in every composed manifest (the local " +
        "distress lane is always-on: the composer always injects it, and a " +
        "manifest without it cannot be put into force)",
    );
  }
  if (webhookCount > 1) {
    issues.push(
      `more than one "${HABEAS_WEBHOOK_RULE_ID}" rule in the manifest; the ` +
        "reserved distress webhook rule must be unique",
    );
  }
  if (issues.length > 0) return issues;

  const webhookRule = rules.find(
    (r) => r.id === HABEAS_WEBHOOK_RULE_ID && isGenuineDerivedHabeasRule(r),
  );
  let webhook: HabeasWebhookTarget | undefined;
  if (webhookRule !== undefined) {
    const host = toArray(webhookRule.match.host)[0];
    const port = toArray(webhookRule.match.port)[0];
    if (typeof host === "string" && typeof port === "number") {
      webhook = { host, port };
    }
  }
  const operator = rules.filter((r) => !isGenuineDerivedHabeasRule(r));
  return findHabeasConflicts(operator, webhook);
}

/** Thrown when an operator ruleset conflicts with the habeas lane. */
export class HabeasConflictError extends Error {
  readonly issues: readonly string[];
  constructor(issues: readonly string[]) {
    super(
      "Castle Wall policy rejected: it would silence the reserved habeas distress " +
        `lane.\n  - ${issues.join("\n  - ")}\nThe habeas lane is the guaranteed ` +
        "distress channel and cannot be removed or shadowed by policy.",
    );
    this.name = "HabeasConflictError";
    this.issues = issues;
  }
}

/** Inputs to {@link composeEffectiveRules}. */
export interface ComposeEffectiveRulesInput {
  /** Operator-authored rules loaded from disk (already schema-validated). */
  operatorRules: readonly AllowlistRule[];
  /** System resolver set for the scoped DNS derivation (#380). */
  resolvers: readonly unknown[];
  /** Validated distress webhook target, when configured. */
  distressWebhook?: HabeasWebhookTarget | undefined;
  /**
   * Validated exclusive-egress gate policy (Unified Protect Slice 1). When
   * present, the composer injects the derived `.agent`-scoped loopback allow
   * rule for the gate channel (`127.0.0.1/32`, gate port, TCP). Absent means
   * no gate rule (the pre-exclusive-egress composition, unchanged).
   */
  exclusiveEgressGate?: ExclusiveEgressGatePolicy | undefined;
  /** Timestamp stamped onto every derived rule. */
  createdAt: string;
}

/**
 * Compose the effective ruleset that gets signed into the manifest:
 *
 *   operator rules  →  habeas-conflict gate (throws HabeasConflictError)
 *                   →  + reserved habeas rules (always)
 *                   →  + scoped DNS derivation (#380; sees the habeas webhook
 *                        hostname rule, so the webhook name stays resolvable)
 *
 * Pure (no I/O) so the always-present and fail-closed properties are unit
 * testable; the daemon supplies resolvers/config.
 */
export function composeEffectiveRules(input: ComposeEffectiveRulesInput): AllowlistRule[] {
  // Reserved derived-gate id (Unified Protect Slice 1): like the habeas
  // reserved ids, "derived_exclusive_egress_gate" is derived, never
  // authored. An operator rule claiming it would either duplicate the id in
  // the signed manifest (wedging the Slice-8 parity gate, which requires
  // EXACTLY one) or, when no gate policy is configured, plant a
  // derived-looking rule the parity/introspection surfaces would
  // misattribute. Rejected up front whether or not a gate policy is present.
  // (Contrast with the DNS derivation, where an operator override wins:
  // that rule is a convenience derivation, not a parity-checked enforcement
  // surface.)
  if (input.operatorRules.some((rule) => rule.id === DERIVED_GATE_RULE_ID)) {
    throw new Error(
      `Castle Wall policy rejected: rule id "${DERIVED_GATE_RULE_ID}" is reserved for the ` +
        "derived exclusive-egress gate rule; reserved rules are derived, never authored.",
    );
  }
  const issues = findHabeasConflicts(input.operatorRules, input.distressWebhook);
  if (issues.length > 0) {
    throw new HabeasConflictError(issues);
  }
  const rules: AllowlistRule[] = [...input.operatorRules];
  rules.push(
    ...deriveHabeasDistressRules({
      webhook: input.distressWebhook,
      createdAt: input.createdAt,
    }),
  );
  const derivedDns = deriveDnsRuleForHostnameRules({
    rules,
    resolvers: input.resolvers,
    createdAt: input.createdAt,
  });
  if (derivedDns) {
    rules.push(derivedDns);
  }
  // Exclusive-egress gate channel (Unified Protect Slice 1): a single
  // derived allow rule pinning the agent's gate channel to loopback TCP on
  // the gate port. `deriveGateAllowRule` re-validates and throws on a
  // malformed policy, so a bad config can never sign a malformed rule.
  if (input.exclusiveEgressGate !== undefined) {
    rules.push(deriveGateAllowRule(input.exclusiveEgressGate, input.createdAt));
  }
  // Self-check: the composed output must pass the same composed-manifest gate
  // the Linux daemon applies before putting a manifest into force
  // ({@link findHabeasConflictsInComposed} / Rust
  // `find_habeas_conflicts_in_composed`). This can only fire on a composer
  // bug (e.g. the lane derivation regressing), and failing HERE — before the
  // manifest is signed — is strictly better than shipping a manifest every
  // conforming daemon will refuse.
  const composedIssues = findHabeasConflictsInComposed(rules);
  if (composedIssues.length > 0) {
    throw new HabeasConflictError(composedIssues);
  }
  return rules;
}
