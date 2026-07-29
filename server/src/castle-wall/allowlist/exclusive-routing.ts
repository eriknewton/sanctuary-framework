/**
 * Exclusive routing manifest composition (Unified Protect Slice 5 S5-4,
 * design rev3 BLOCKER-1 fix; requires the merged + drill-proven S5-0
 * two-confined-uid origin model, #930).
 *
 * THE PROBLEM (review BLOCKER-1). Simply wiring the gate/pf layer into the
 * install flow additively would not deliver fine-grained control: the coarse
 * program's provisioned endpoint rules (`provisioned-<harness>-*`,
 * `scope: {}` = all wrapped agents) would still let the agent egress DIRECTLY
 * to every declared endpoint without transiting the gate. Exclusive mode is a
 * ROUTING-MODEL change, not an addition.
 *
 * THE MODEL (design "The exclusive routing model"): when fine-grained mode is
 * claimed for an agent -
 *   1. the agent's signed-manifest posture is default-deny with NO direct
 *      off-box endpoint allows: the provisioned endpoint rules are RE-SCOPED
 *      AWAY FROM THE AGENT to the gate principal
 *      (`scope.uids = [gate_uid]`, the S5-0 per-principal axis) - that
 *      re-scope happens at PUBLISH time (`buildProvisionedEgressRules`
 *      exclusive routing), so the on-disk rule files (the daemon's signing
 *      source) stay the single source of truth;
 *   2. the manifest allows the agent exactly the gate channel (the derived
 *      gate rule, now bound to the agent principal) plus explicitly justified
 *      reserved lanes (the habeas distress lanes - the guaranteed distress
 *      channel is deliberately NOT routed through the gate, so a gate
 *      compromise can never silence distress);
 *   3. a COMPOSE-TIME ASSERTION fails CLOSED (no manifest, no arm) if any
 *      agent-reachable direct off-box endpoint allow survives composition.
 *
 * COARSE-ONLY FALLBACK IS AN EXPLICIT, AUDITED MODE (design answer 2 +
 * ordering rule). In coarse-only mode the agent needs the ORIGINAL
 * agent-scoped endpoint rules (it has no gate), so composition falls back to
 * the coarse scoping - but ONLY as an explicit mode switch that (a) REFUSES
 * to compose while any gate-scoped provisioned residue is still on disk
 * ("never a residue of both models at once"), and (b) REQUIRES a successful
 * audit emission with the DISTINCT local audit operation string
 * {@link EXCLUSIVE_ROUTING_COARSE_FALLBACK_AUDIT_OP} (never a widened shared
 * enum) before the composed rules are returned - an unaudited fallback must
 * not compose. S5-P (merged in the same stack, one PR below) already renders
 * the coarse-only state as a DISTINCT non-green status on every posture
 * surface, satisfying the design's hard ordering constraint (no coarse-only-
 * capable code before all-surface rendering exists).
 *
 * JUSTIFIED RESERVED LANES (exact, shape-verified - never id-trusted):
 *   - the derived gate-channel rule (`derived_exclusive_egress_gate`):
 *     verified loopback-only, gate-port-pinned, agent-principal-scoped;
 *   - the habeas distress lanes (`reserved_habeas_distress_local` /
 *     `_webhook`): verified via the shipped exact-shape recognizer
 *     `isGenuineDerivedHabeasRule` (a rule merely CLAIMING a reserved id is a
 *     violation, not a lane). The webhook lane is an off-box allow scoped to
 *     the distress emitter - an EXPLICITLY documented residual, surfaced in
 *     the composition report, never silent.
 *   - the derived DNS rule (`derived_dns_for_hostname_rules`) is checked like
 *     any other rule (NOT exempt): its scope is the union of its hostname-
 *     rule parents' scopes, so in a clean exclusive composition it binds to
 *     the gate principal + the habeas emitter and never reaches the agent -
 *     the design's "no direct DNS for the agent; the gate resolves"
 *     recommendation falls out structurally.
 *
 * PLATFORM BOUND (stated plainly): exclusive routing is macOS-ONLY. The
 * `scope.uids` axis is the S5-0 macOS extension; the Linux (Rust) daemon
 * fail-closed REFUSES uids-bearing rule files by design
 * (castle-wall-daemon/src/policy.rs pins that refusal), and the whole
 * pf/gate stack is a macOS subsystem. The Linux fine-grained layer is a
 * named future design, not this module.
 *
 * HONESTY BOUNDS. This is the composition LIBRARY; it is WIRED (S5-6): the
 * signing daemon (`castle-wall/runtime/macos-daemon.ts`) routes every
 * manifest compose through it whenever the exclusive-routing marker
 * (`allowlist/routing-marker.ts`) is present, and the install/repair flows'
 * degrade path routes the coarse-only fallback through it. It advances no
 * capability claim (code; the Erik-present S5-DRILL is still owed). The
 * static endpoint verify (`verifyProvisionedEgressStatically`)
 * is scope-blind by construction, so under exclusive routing it verifies the
 * DESTINATION set only; the as-principal reachability proof is the drill's
 * as-gate-uid / as-agent-uid legs, never this library.
 */

import { OBSERVE_PROMOTED_RULE_ID_PREFIX } from "../constants.js";
import type { AllowlistRule, RuleScope } from "./schema.js";
import {
  DERIVED_GATE_RULE_ID,
  deriveGateAllowRule,
  validateExclusiveEgressGatePolicy,
  type ExclusiveEgressGatePolicy,
} from "./gate-derivation.js";
import { DERIVED_DNS_RULE_ID } from "./dns-derivation.js";
import {
  HABEAS_WEBHOOK_RULE_ID,
  HABEAS_RULE_ID_PREFIX,
  isGenuineDerivedHabeasRule,
  composeEffectiveRules,
  type ComposeEffectiveRulesInput,
} from "./habeas-port.js";

/**
 * DISTINCT local audit operation string for the coarse-only fallback
 * composition (design §7: never widen a shared enum; a distinct op so audit
 * consumers, SIEM export, and the evidence pack can attribute the mode switch
 * exactly). An `AuditLog` entry `operation` value only - never dispatched to
 * the approval gate, carries no tier of its own.
 */
export const EXCLUSIVE_ROUTING_COARSE_FALLBACK_AUDIT_OP =
  "exclusive_routing_coarse_fallback";

/** The generic provisioned-rule id prefix (all harnesses): `provisioned-`. */
const PROVISIONED_RULE_ID_GENERIC_PREFIX = "provisioned-";

/** The confined agent's identity axes for the reachability check. */
export interface ConfinedAgentIdentity {
  agent_id: string;
  agent_template: string;
}

/** The two confined principals of the exclusive routing model (S5-0). */
export interface ExclusiveRoutingPrincipals {
  /** The wrapped agent's dedicated service-account uid. */
  agent_uid: number;
  /** The dedicated `sanctuary-gate` service-account uid. */
  gate_uid: number;
  /**
   * The confined agent's id/template identity. Used to decide whether an
   * `agent_ids`/`template_ids`-scoped rule covers the agent. REQUIRED:
   * without it the assertion could not classify id-scoped rules and would
   * have to guess; fail-closed means no guessing.
   */
  agent: ConfinedAgentIdentity;
}

/** One rule the assertion rejected, with the reason it reaches the agent. */
export interface ExclusiveRoutingViolation {
  rule_id: string;
  reason: string;
}

/** Thrown when the compose-time assertion finds an agent-reachable allow. */
export class ExclusiveRoutingViolationError extends Error {
  readonly violations: readonly ExclusiveRoutingViolation[];
  constructor(violations: readonly ExclusiveRoutingViolation[]) {
    super(
      "Exclusive routing composition rejected (fail closed: no manifest, no arm): " +
        "agent-reachable direct endpoint allow(s) survived composition.\n  - " +
        violations.map((v) => `${v.rule_id}: ${v.reason}`).join("\n  - ") +
        "\nIn exclusive mode the agent's only sanctioned off-box path is the gate; " +
        "every endpoint allow must bind to the gate principal.",
    );
    this.name = "ExclusiveRoutingViolationError";
    this.violations = violations;
  }
}

/**
 * Thrown when a coarse-only fallback composition finds uid-scoped allow
 * residue on the input ruleset - the "residue of both models at once" state
 * the design forbids. Coarse rules are `scope: {}` by construction, so ANY
 * lingering `scope.uids` binding on an operator allow (provisioned or not) is
 * exclusive-model residue. The caller must republish the provisioned rules
 * coarse (one explicit signed republish) before composing the fallback.
 */
export class ExclusiveRoutingResidueError extends Error {
  readonly residueRuleIds: readonly string[];
  constructor(residueRuleIds: readonly string[]) {
    super(
      "Coarse-only fallback composition rejected: uid-scoped allow rule(s) " +
        `still present (${residueRuleIds.join(", ")}). ` +
        "Coarse rules are scope:{} by construction; a lingering scope.uids binding is " +
        "exclusive-model residue. The fallback is an explicit mode switch, never a " +
        "residue of both models at once: republish the provisioned rules with coarse " +
        "routing first.",
    );
    this.name = "ExclusiveRoutingResidueError";
    this.residueRuleIds = residueRuleIds;
  }
}

/** The composition report (what was allowed and WHY, for posture + audit). */
export interface ExclusiveRoutingCompositionReport {
  /** Reserved lanes admitted by exact shape (gate channel + habeas). */
  justified_lane_ids: string[];
  /** Endpoint allows bound to the gate principal (the re-scoped set). */
  gate_scoped_rule_ids: string[];
  /**
   * Loopback-only allows admitted as not-off-box (inert to exclusivity: the
   * pf anchor confines agent loopback to the gate port regardless).
   */
  loopback_only_rule_ids: string[];
  /**
   * The EXPLICITLY documented residuals (Erik-visible, never silent): today
   * exactly the habeas webhook lane when configured - an off-box allow the
   * distress channel keeps outside the gate by design.
   */
  documented_residual_ids: string[];
}

function toArray<T>(value: T | T[] | undefined): T[] {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

/**
 * Canonical JSON of a value: deep key-sorted so property order can never mask
 * or fake a match. Mirrors the egress-gate parity guard's `normalizeRule`
 * (`egress-gate/parity.ts`); kept LOCAL rather than imported because
 * `egress-gate` already depends on `castle-wall/allowlist`, so importing back
 * would introduce a module cycle. Used for the derived-gate-rule byte-identity
 * check (an extra/mutated field changes the canonical string => rejected).
 */
function canonicalJson(value: unknown): string {
  return JSON.stringify(deepSortKeys(value));
}

function deepSortKeys(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(deepSortKeys);
  }
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort()) {
      out[key] = deepSortKeys(record[key]);
    }
    return out;
  }
  return value;
}

function scopeIsAll(scope: RuleScope | undefined): boolean {
  if (scope === undefined) return true;
  const hasAgents = (scope.agent_ids?.length ?? 0) > 0;
  const hasTemplates = (scope.template_ids?.length ?? 0) > 0;
  const hasUids = (scope.uids?.length ?? 0) > 0;
  return !hasAgents && !hasTemplates && !hasUids;
}

/**
 * True iff an allow rule's scope can cover the confined AGENT under the S5-0
 * evaluation model (the three axes compose as an OR): an empty scope covers
 * every wrapped agent; `uids` naming the agent uid covers it; `agent_ids` /
 * `template_ids` naming the agent's identity cover it. A rule bound ONLY to
 * other uids/ids does not. Deliberately NOT `match.ts:ruleScopeCoversAgent`:
 * that check has no uid identity for its subject (observe rows carry no uid
 * attribution) and treats a uids-only scope as not-covering, whereas this
 * assertion KNOWS the agent's uid and must treat `uids: [agent_uid]` as
 * reaching the agent.
 */
export function allowRuleScopeReachesAgent(
  scope: RuleScope | undefined,
  principals: ExclusiveRoutingPrincipals,
): boolean {
  if (scopeIsAll(scope)) return true;
  const s = scope as RuleScope;
  if ((s.uids ?? []).includes(principals.agent_uid)) return true;
  if ((s.agent_ids ?? []).includes(principals.agent.agent_id)) return true;
  if ((s.template_ids ?? []).includes(principals.agent.agent_template)) return true;
  return false;
}

/** True iff a string is an IPv4/IPv6 loopback literal. */
function isLoopbackIpLiteral(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower === "::1") return true;
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(lower);
}

/** True iff a CIDR is fully contained in loopback space. */
function isLoopbackCidr(cidr: string): boolean {
  const lower = cidr.toLowerCase();
  if (lower === "::1/128") return true;
  const m = /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}\/(\d{1,2})$/.exec(lower);
  if (m === null) return false;
  return Number(m[1]) >= 8;
}

/**
 * True iff a rule is PROVABLY loopback-only: at least one destination axis is
 * present, every present `ip`/`cidr` entry is loopback, and NO name axis
 * (`host`/`host_pattern`) exists (names resolve anywhere, so a hostname rule
 * is never loopback-only). A rule with ONLY a `port` axis matches any
 * destination on that port and is NOT loopback-only.
 */
export function ruleIsLoopbackOnly(rule: AllowlistRule): boolean {
  const m = rule.match;
  if (m.host !== undefined || m.host_pattern !== undefined) return false;
  const ips = toArray(m.ip);
  const cidrs = toArray(m.cidr);
  if (ips.length === 0 && cidrs.length === 0) return false;
  return (
    ips.every((ip) => isLoopbackIpLiteral(ip)) &&
    cidrs.every((cidr) => isLoopbackCidr(cidr))
  );
}

/**
 * THE COMPOSE-TIME ASSERTION (design model point 1, fail-closed): scan a
 * COMPOSED ruleset and throw {@link ExclusiveRoutingViolationError} if any
 * agent-reachable direct off-box endpoint ALLOW survives. Returns the
 * composition report on success. Pure; no I/O.
 *
 * Classification, in order, for each `disposition: "allow"` rule:
 *   1. reserved habeas ids: must be GENUINE (exact shape) - a rule merely
 *      claiming the id is a violation. Genuine local lane => justified;
 *      genuine webhook lane => justified + documented residual (off-box by
 *      design, outside the gate so gate compromise cannot silence distress).
 *   2. the derived gate rule: must be loopback-only, pinned to the policy's
 *      gate port, and scoped to exactly the agent principal => justified.
 *      Any other shape claiming the id is a violation.
 *   3. provably loopback-only rules: admitted (not off-box; the pf anchor
 *      confines agent loopback to the gate port regardless) and reported.
 *   4. everything else: agent-reachable scope => VIOLATION; gate-only scope
 *      => reported as gate-scoped. Deny/prompt rules never widen and are
 *      skipped.
 */
export function assertExclusiveRoutingComposition(
  rules: readonly AllowlistRule[],
  input: {
    principals: ExclusiveRoutingPrincipals;
    /** The validated gate policy the composition was built with. */
    gatePolicy: ExclusiveEgressGatePolicy;
  },
): ExclusiveRoutingCompositionReport {
  const violations: ExclusiveRoutingViolation[] = [];
  const report: ExclusiveRoutingCompositionReport = {
    justified_lane_ids: [],
    gate_scoped_rule_ids: [],
    loopback_only_rule_ids: [],
    documented_residual_ids: [],
  };
  const { principals, gatePolicy } = input;

  for (const rule of rules) {
    if (rule.disposition !== "allow") continue;

    // 1. Reserved habeas lanes: exact-shape genuine or violation.
    if (rule.id.startsWith(HABEAS_RULE_ID_PREFIX)) {
      if (!isGenuineDerivedHabeasRule(rule)) {
        violations.push({
          rule_id: rule.id,
          reason:
            "claims a reserved habeas distress id but is not a genuine derived reserved rule",
        });
        continue;
      }
      report.justified_lane_ids.push(rule.id);
      if (rule.id === HABEAS_WEBHOOK_RULE_ID) {
        report.documented_residual_ids.push(rule.id);
      }
      continue;
    }

    // 2. The derived gate-channel rule: must be BYTE-IDENTICAL (canonical
    // JSON, modulo `created_at`) to a fresh re-derivation from the
    // single-source gate policy - the exact re-derive-and-compare the
    // egress-gate parity guard already uses (`egress-gate/parity.ts`,
    // `deriveGateAllowRule(policy, created_at, { scope_to_agent_uid: true })`
    // vs canonical-JSON of the manifest rule). A field-by-field shape check is
    // NOT enough: it neither forbids EXTRA fields (a rule could carry
    // `protocol: "udp"`, a second axis, or any smuggled property while every
    // checked field passes) nor pins every field, so only exact equality
    // against the canonical derivation proves this is the justified gate lane
    // and nothing wider. Re-derive with the claimed rule's own `created_at` so
    // an honest timestamp is not read as drift; every other byte must match.
    if (rule.id === DERIVED_GATE_RULE_ID) {
      const expected = deriveGateAllowRule(gatePolicy, rule.created_at, {
        scope_to_agent_uid: true,
      });
      if (canonicalJson(rule) !== canonicalJson(expected)) {
        violations.push({
          rule_id: rule.id,
          reason:
            "claims the derived gate-channel id but is not byte-identical to the " +
            "single-source gate derivation (expected the agent-principal-scoped " +
            `127.0.0.1/32:${gatePolicy.gate_port} TCP loopback rule scoped to uids ` +
            `[${principals.agent_uid}]; any extra field, protocol, port, destination, ` +
            "or scope deviation is rejected)",
        });
        continue;
      }
      report.justified_lane_ids.push(rule.id);
      continue;
    }

    // 3. Provably loopback-only allows are not off-box.
    if (ruleIsLoopbackOnly(rule)) {
      report.loopback_only_rule_ids.push(rule.id);
      continue;
    }

    // 4. Direct off-box allow: agent-reachable => violation (this includes
    // the derived DNS rule when its parent union reaches the agent).
    if (allowRuleScopeReachesAgent(rule.scope, principals)) {
      // 2026-07-27 round-3 R3(ii): an observe-PROMOTED rule with a
      // pre-exclusive (template/agent) scope has a PRODUCT recovery path;
      // name it here, because this error is exactly what the operator sees
      // when a coarse-era promoted rule bricks the exclusive compose, and
      // the generic residue advice ("republish the provisioned rules")
      // does not apply to it.
      const observeRemedy = rule.id.startsWith(OBSERVE_PROMOTED_RULE_ID_PREFIX)
        ? " Remedy: if this rule was promoted by 'observe promote' before exclusive routing was armed," +
          " run 'sanctuary castle-wall observe promote --all' on this fortress (it re-scopes promoted" +
          " rules ITS OWN signed manifest owns to the gate principal, under the same Tier-1 approval," +
          " even with no pending candidates). An OPERATOR-AUTHORED rule file that merely carries this" +
          " id prefix is not promote-owned and must be re-scoped or removed manually" +
          " (delete its file from policy/egress/rules/)."
        : "";
      violations.push({
        rule_id: rule.id,
        reason:
          (rule.id === DERIVED_DNS_RULE_ID
            ? "the derived DNS allow's parent-scope union reaches the agent " +
              "(an agent-reachable hostname allow exists; the agent must have NO direct DNS - the gate resolves)"
            : scopeIsAll(rule.scope)
              ? "unscoped allow (scope: {} covers every wrapped agent) grants the agent a direct off-box endpoint"
              : "scope covers the confined agent (uids/agent_ids/template_ids axis names it)") + observeRemedy,
      });
      continue;
    }
    if ((rule.scope?.uids ?? []).includes(principals.gate_uid)) {
      report.gate_scoped_rule_ids.push(rule.id);
    }
  }

  if (violations.length > 0) {
    throw new ExclusiveRoutingViolationError(violations);
  }
  return report;
}

/** The audit record the coarse-only fallback REQUIRES to be emitted. */
export interface CoarseFallbackAuditRecord {
  /** Always {@link EXCLUSIVE_ROUTING_COARSE_FALLBACK_AUDIT_OP}. */
  operation: typeof EXCLUSIVE_ROUTING_COARSE_FALLBACK_AUDIT_OP;
  /** Operator-meaningful reason the exclusive stack could not be used. */
  reason: string;
  /** The agent uid the fallback applies to. */
  agent_uid: number;
  /** Provisioned rule ids composed in coarse (agent-reachable) scope. */
  coarse_provisioned_rule_ids: string[];
}

/** The routing request for {@link composeExclusiveRoutingRules}. */
export type ExclusiveRoutingRequest =
  | {
      readonly mode: "exclusive";
      readonly principals: ExclusiveRoutingPrincipals;
    }
  | {
      readonly mode: "coarse-only";
      readonly agent_uid: number;
      /** Why the exclusive stack is unavailable (goes into the audit record). */
      readonly reason: string;
      /**
       * REQUIRED audit emitter. The fallback composition completes ONLY after
       * this resolves; a throw propagates and the composition FAILS (an
       * unaudited silent degrade is exactly what invariant 5 forbids). This
       * is a compose-time control-plane write, not a per-flow decision, so
       * blocking on it is correct (contrast the #912 per-CONNECT rule).
       */
      readonly audit: (record: CoarseFallbackAuditRecord) => void | Promise<void>;
    };

/** The composed result: the effective rules + the mode they embody. */
export interface ExclusiveRoutingComposition {
  rules: AllowlistRule[];
  mode: "exclusive" | "coarse-only";
  /** Present in exclusive mode: what the assertion admitted and why. */
  report?: ExclusiveRoutingCompositionReport;
}

/**
 * Compose the effective manifest ruleset under an explicit routing mode.
 * This WRAPS the shipped composition chokepoint ({@link composeEffectiveRules}
 * - habeas lanes, derived DNS, gate rule, composed-manifest self-check) and
 * adds the exclusive-routing semantics on top:
 *
 *   - `exclusive`: requires a gate policy whose `agent_uid` matches the
 *     principals (mismatch throws - a manifest composed for one agent must
 *     never be asserted against another's principals); composes with the
 *     gate-channel rule bound to the agent principal; then runs
 *     {@link assertExclusiveRoutingComposition} over the COMPOSED output
 *     (fail-closed: no manifest on any violation).
 *   - `coarse-only`: REFUSES if any gate-scoped provisioned residue is on the
 *     input (republish coarse first - never both models at once); composes
 *     WITHOUT a gate policy (no gate channel in coarse mode); then REQUIRES
 *     the audit emission before returning.
 *
 * Async because the fallback's audit emitter may be. Pure over its inputs
 * otherwise; no I/O of its own.
 */
export async function composeExclusiveRoutingRules(input: {
  /** The base composition inputs (operator rules, resolvers, webhook, ...). */
  base: Omit<ComposeEffectiveRulesInput, "gateRuleScopeToAgentUid">;
  routing: ExclusiveRoutingRequest;
}): Promise<ExclusiveRoutingComposition> {
  const { base, routing } = input;

  if (routing.mode === "exclusive") {
    const gatePolicy = validateExclusiveEgressGatePolicy(base.exclusiveEgressGate);
    if (gatePolicy === null) {
      throw new ExclusiveRoutingViolationError([
        {
          rule_id: "(gate policy)",
          reason:
            "exclusive routing requires a valid exclusive-egress gate policy; none was supplied",
        },
      ]);
    }
    if (gatePolicy.agent_uid !== routing.principals.agent_uid) {
      throw new ExclusiveRoutingViolationError([
        {
          rule_id: "(gate policy)",
          reason:
            `gate policy agent_uid ${gatePolicy.agent_uid} != principals agent_uid ` +
            `${routing.principals.agent_uid} (cross-principal composition refused)`,
        },
      ]);
    }
    if (
      routing.principals.gate_uid === routing.principals.agent_uid ||
      !Number.isInteger(routing.principals.gate_uid) ||
      routing.principals.gate_uid <= 0
    ) {
      throw new ExclusiveRoutingViolationError([
        {
          rule_id: "(principals)",
          reason: `gate_uid ${String(routing.principals.gate_uid)} must be a positive integer distinct from the agent uid`,
        },
      ]);
    }
    const rules = composeEffectiveRules({
      ...base,
      gateRuleScopeToAgentUid: true,
    });
    const report = assertExclusiveRoutingComposition(rules, {
      principals: routing.principals,
      gatePolicy,
    });
    return { rules, mode: "exclusive", report };
  }

  // coarse-only fallback: explicit, residue-free, audited.
  //
  // Coarse rules are `scope: {}` by construction (all wrapped agents, no uid
  // axis), so ANY operator ALLOW that still carries a `scope.uids` binding is
  // exclusive-model residue - not only the `provisioned-*` rules. A
  // NON-provisioned operator allow scoped to the gate uid (or the agent uid)
  // would otherwise survive the coarse compose, and the derived-DNS rule would
  // inherit that uid-scoped parent and RE-INTRODUCE the gate-scoped residue
  // into the composed output. Reject on ANY uids-scoped allow: the fallback is
  // an explicit mode switch, never a residue of both models at once. (Deny/
  // prompt rules never grant off-box reach, so scoping them is inert here.)
  const residue = base.operatorRules
    .filter(
      (rule) =>
        rule.disposition === "allow" && (rule.scope?.uids?.length ?? 0) > 0,
    )
    .map((rule) => rule.id);
  if (residue.length > 0) {
    throw new ExclusiveRoutingResidueError(residue);
  }
  const rules = composeEffectiveRules({
    ...base,
    // No gate channel in coarse mode: the gate is not live/present, and a
    // derived gate rule pointing at a dead port would be a green-looking
    // artifact of the abandoned exclusive bring-up.
    exclusiveEgressGate: undefined,
    gateRuleScopeToAgentUid: false,
  });
  const coarseProvisionedRuleIds = rules
    .filter((rule) => rule.id.startsWith(PROVISIONED_RULE_ID_GENERIC_PREFIX))
    .map((rule) => rule.id);
  // The audit emission is REQUIRED: a throw propagates and no rules are
  // returned. Emit AFTER a successful compose (never audit a fallback that
  // did not happen) and BEFORE returning (never return an unaudited one).
  await routing.audit({
    operation: EXCLUSIVE_ROUTING_COARSE_FALLBACK_AUDIT_OP,
    reason: routing.reason,
    agent_uid: routing.agent_uid,
    coarse_provisioned_rule_ids: coarseProvisionedRuleIds,
  });
  return { rules, mode: "coarse-only" };
}
