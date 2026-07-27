/**
 * Pure synthesis: candidate observations -> proposed `AllowlistRule` objects
 * (scoping doc section 2.4; CI DoD test 2). No I/O.
 *
 * Mirrors the shipped pure-planner discipline of
 * `allowlist/gate-derivation.ts`'s `deriveGateAllowRule`: every synthesized
 * rule is run through the EXISTING `validateRule` before it can ever be
 * offered for promotion. A candidate that cannot pass validation yields
 * `null` -- it is dropped, never offered, and never signed into the
 * manifest (fail-closed: an unvalidatable rule is worse than no rule).
 */

import { createHash } from "node:crypto";
import net from "node:net";

import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../constants.js";
import { validateRule, type AllowlistRule, type RuleMatch, type RuleScope } from "../allowlist/schema.js";
import {
  DEFAULT_OBSERVE_GRANULARITY,
  type CandidateObservation,
  type ObserveGranularity,
} from "./types.js";

/**
 * Naive registered-domain heuristic: the last two dot-separated labels of a
 * hostname (e.g. `api.example.com` -> `example.com`). This is NOT a real
 * public-suffix-list eTLD+1 lookup (this repo ships no such dependency) and
 * can mis-widen a multi-label public suffix (e.g. `foo.co.uk` naively yields
 * `co.uk`, not `foo.co.uk`). Documented honestly rather than silently
 * shipped as authoritative: callers that offer this granularity MUST show
 * the resulting widened match to the operator before promote (D-Q2 default
 * is exact host; this is the explicit-opt-in path only). Returns `null` for
 * an IP literal or a single-label host, since there is no "domain" to widen
 * to for either -- an eTLD+1 grant on an IP-only observation would silently
 * become an ip/cidr grant instead, which is not what the operator asked for.
 */
export function naiveRegisteredDomain(host: string): string | null {
  if (net.isIP(host) !== 0) return null;
  const labels = host.split(".").filter((label) => label.length > 0);
  if (labels.length < 2) return null;
  return labels.slice(-2).join(".");
}

/**
 * A small BUILT-IN set of common two-label public suffixes under which the
 * naive last-two-labels heuristic would produce a public-suffix-WIDE grant
 * (e.g. `foo.co.uk` -> `co.uk` -> `*.co.uk` allows every `.co.uk` site).
 * This is NOT a full public-suffix list (no PSL dependency) -- it is a
 * deliberately conservative deny-list of the most common multi-label
 * suffixes, so that an explicit `per_template_etld1` widening REFUSES to
 * synthesize a rule when the naive registered domain lands on one of these
 * (two-family gate FIX 3). The candidate is then dropped, never offered for
 * promote, rather than silently signing a suffix-wide grant. An operator who
 * genuinely wants such a host promotes it at the exact-host default instead.
 */
export const REFUSED_MULTI_LABEL_PUBLIC_SUFFIXES: ReadonlySet<string> = new Set([
  "co.uk", "org.uk", "me.uk", "net.uk", "ac.uk", "gov.uk", "sch.uk", "ltd.uk", "plc.uk", "nhs.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au", "asn.au",
  "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "geek.nz",
  "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "gr.jp",
  "com.br", "net.br", "org.br", "gov.br", "edu.br",
  "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "gov.in",
  "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
  "co.za", "org.za", "gov.za", "net.za",
  "com.mx", "org.mx", "gob.mx", "edu.mx",
  "co.kr", "or.kr", "ne.kr", "go.kr",
  "com.sg", "edu.sg", "gov.sg", "org.sg",
  "com.hk", "org.hk", "gov.hk", "edu.hk",
  "com.tr", "gov.tr", "org.tr", "net.tr",
  "com.tw", "org.tw", "gov.tw", "edu.tw",
  "co.il", "org.il", "gov.il", "ac.il",
  "com.ar", "gob.ar", "org.ar", "net.ar",
]);

/**
 * The registered domain a `per_template_etld1` widening would grant `*.` of,
 * or `null` when that widening MUST be refused: an IP literal / single-label
 * host (no domain to widen to), or a naive result that lands on a known
 * multi-label public suffix (a suffix-wide grant the operator did not ask
 * for). This is the single chokepoint both the synthesis path and its tests
 * consult, so the refusal cannot drift between them.
 */
export function widenableRegisteredDomain(host: string): string | null {
  const domain = naiveRegisteredDomain(host);
  if (domain === null) return null;
  if (REFUSED_MULTI_LABEL_PUBLIC_SUFFIXES.has(domain)) return null;
  return domain;
}

/**
 * The id prefix EVERY observe-promoted rule carries. Single source shared by
 * `stableCandidateRuleId` below and the CLI's `FilesystemManifestStorage`
 * orphan-cleanup scoping (cli/castle-wall-observe.ts), so the publisher's
 * "which rule files does observe own" matcher can never drift from the ids
 * this module actually mints (a guard must share its matcher with the code
 * it guards).
 */
export const OBSERVE_PROMOTED_RULE_ID_PREFIX = "derived-observe-";

function stableCandidateRuleId(
  observation: CandidateObservation,
  granularity: ObserveGranularity,
): string {
  const basis = JSON.stringify([
    "observe-v1",
    granularity,
    observation.agent_template,
    observation.agent_id,
    observation.host,
    observation.ip,
    observation.port,
    observation.protocol,
  ]);
  const digest = createHash("sha256").update(basis).digest("hex");
  return `${OBSERVE_PROMOTED_RULE_ID_PREFIX}${digest.slice(0, 20)}`;
}

/**
 * Routing mode for a promoted rule's SCOPE (2026-07-27 enforcement-reach fix,
 * Option A). Mirrors `provision/egress.ts`'s `ProvisionedEgressRouting` shape
 * (kept local to avoid an observe->provision import edge; the AXIS is reused,
 * not reinvented -- `scope.uids`, the S5-0 per-principal axis):
 *
 *  - `coarse` (default; the shipped shape): template/agent-scoped per the
 *    operator's granularity choice. The confined agent reaches the promoted
 *    destination DIRECTLY.
 *  - `exclusive`: the rule is SCOPED AWAY FROM THE AGENT to the gate
 *    principal (`scope.uids = [gate_uid]`), exactly like the provisioned
 *    endpoint rules under exclusive routing. REQUIRED whenever the fortress
 *    carries the exclusive-routing marker: now that promoted rules reach the
 *    composer (`policy/egress/rules/`), a template/agent-scoped promoted rule
 *    would be an agent-reachable direct off-box allow, which the exclusive
 *    compose-time assertion rejects by THROWING -- no manifest, no arm, a
 *    bricked policy reload. Gate-uid scoping keeps the reload composable and
 *    routes the promoted destination through the gate, the only sanctioned
 *    off-box path in exclusive mode.
 */
export type PromoteRouting =
  | { readonly mode: "coarse" }
  | { readonly mode: "exclusive"; readonly gate_uid: number };

function buildMatch(
  observation: CandidateObservation,
  granularity: ObserveGranularity,
): RuleMatch | null {
  const protocol = observation.protocol === "udp" ? "udp" : "tcp";

  if (granularity === "per_template_etld1") {
    // Never widen an IP-only observation to a "domain" -- there is no
    // hostname to widen (adversarial review L2: the widening effect must be
    // visible and honest, never a silent scope change to a different axis).
    if (!observation.host) return null;
    // REFUSE a widening that would land on a known multi-label public suffix
    // (e.g. `foo.co.uk` -> `*.co.uk`): that is a suffix-wide grant the
    // operator never asked for (two-family gate FIX 3). `null` here drops
    // the candidate rather than signing an over-broad rule.
    const registeredDomain = widenableRegisteredDomain(observation.host);
    if (!registeredDomain) return null;
    return {
      host: [registeredDomain],
      host_pattern: `*.${registeredDomain}`,
      port: [observation.port],
      protocol,
    };
  }

  // per_template_domain / per_instance_domain: the narrowest honest grant --
  // exactly the observed host, or the observed IP when no hostname was seen.
  if (observation.host) {
    return { host: [observation.host], port: [observation.port], protocol };
  }
  if (observation.ip) {
    return { ip: [observation.ip], port: [observation.port], protocol };
  }
  return null;
}

function buildScope(
  observation: CandidateObservation,
  granularity: ObserveGranularity,
  routing: PromoteRouting,
): RuleScope {
  if (routing.mode === "exclusive") {
    // Exclusive routing: bind to the gate principal ONLY. The scope axes
    // compose as an OR at enforcement, so ALSO carrying the template/agent
    // axis would keep the rule agent-reachable and defeat the whole point.
    return { uids: [routing.gate_uid] };
  }
  return granularity === "per_instance_domain"
    ? { agent_ids: [observation.agent_id] }
    : { template_ids: [observation.agent_template] };
}

function describeCandidateRule(
  observation: CandidateObservation,
  granularity: ObserveGranularity,
  routing: PromoteRouting,
): string {
  const dest = observation.host ?? observation.ip;
  const widened =
    granularity === "per_template_etld1"
      ? " (widened to the registered domain; an explicit operator choice, never the default)"
      : "";
  const routingNote =
    routing.mode === "exclusive"
      ? " Exclusive routing: bound to the sanctuary-gate principal (S5-0 uids scope); the agent transits the gate."
      : "";
  return (
    `Observe/Learn candidate: ${observation.agent_template} reached ` +
    `${dest}:${observation.port}/${observation.protocol}${widened}, seen ` +
    `${observation.times_seen}x between ${observation.first_seen} and ${observation.last_seen}.` +
    routingNote
  );
}

/**
 * Synthesize ONE candidate into an `AllowlistRule`, or `null` when the
 * candidate cannot yield a valid rule (no usable host/IP, or the resulting
 * rule fails `validateRule`). Never throws -- an unsynthesizable candidate is
 * dropped, not an error. `routing` decides the SCOPE axis (see
 * {@link PromoteRouting}); an exclusive routing with an invalid gate uid
 * fails `validateRule` (positive-integer uids) and drops the candidate,
 * never signs a malformed scope.
 */
export function synthesizeCandidateRule(
  observation: CandidateObservation,
  createdAt: string,
  granularity: ObserveGranularity = DEFAULT_OBSERVE_GRANULARITY,
  routing: PromoteRouting = { mode: "coarse" },
): AllowlistRule | null {
  const match = buildMatch(observation, granularity);
  if (!match) return null;

  const rule: AllowlistRule = {
    id: stableCandidateRuleId(observation, granularity),
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    created_at: createdAt,
    description: describeCandidateRule(observation, granularity, routing),
    match,
    scope: buildScope(observation, granularity, routing),
    disposition: "allow",
    derived: true,
  };

  return validateRule(rule).length === 0 ? rule : null;
}

export interface SynthesizeCandidateRulesResult {
  rules: AllowlistRule[];
  /** Candidates that could not synthesize a valid rule (dropped, never offered). */
  dropped: CandidateObservation[];
}

/**
 * Synthesize a batch of candidates. `granularityFor` lets a caller (the CLI)
 * apply a per-row granularity choice; defaults to the D-Q2 exact-host
 * default for every row when omitted.
 */
export function synthesizeCandidateRules(
  observations: readonly CandidateObservation[],
  createdAt: string,
  granularityFor?: (observation: CandidateObservation) => ObserveGranularity,
  routing: PromoteRouting = { mode: "coarse" },
): SynthesizeCandidateRulesResult {
  const rules: AllowlistRule[] = [];
  const dropped: CandidateObservation[] = [];
  for (const observation of observations) {
    const granularity = granularityFor ? granularityFor(observation) : DEFAULT_OBSERVE_GRANULARITY;
    const rule = synthesizeCandidateRule(observation, createdAt, granularity, routing);
    if (rule) {
      rules.push(rule);
    } else {
      dropped.push(observation);
    }
  }
  return { rules, dropped };
}
