/**
 * Sanctuary WP-V1.3-6 Xi-3 policy conflict detector.
 *
 * Pure, local comparison between a compiled English policy draft and a
 * normalized snapshot of the active Principal Policy. No substrate selector,
 * no network, no persistence.
 */

import type { PrincipalPolicy, Tier2Config } from "../principal-policy/types.js";
import { DEFAULT_POLICY } from "../principal-policy/loader.js";
import type {
  CompiledPolicy,
  CompiledPolicyRule,
} from "./english-policy-compiler.js";

export type PolicyConflictType =
  | "direct_override"
  | "partial_overlap"
  | "contradiction";

export type PolicyConflictSeverity = "low" | "medium" | "high";

export type PolicyRuleEffect = "allow" | "deny" | "set";

export interface PrincipalPolicyRule {
  rule_id: string;
  capability: string;
  effect: PolicyRuleEffect;
  source: "tier1_always_approve" | "tier3_always_allow" | "tier2_anomaly";
  agent_id?: string;
  active_window?: {
    start_hour?: number;
    end_hour?: number;
  };
  value?: unknown;
  is_default?: boolean;
}

export interface PolicyConflict {
  conflict_id: string;
  candidate_policy: CompiledPolicy;
  existing_policy: PrincipalPolicyRule;
  conflict_type: PolicyConflictType;
  severity: PolicyConflictSeverity;
  explanation: string;
  affected_capability: string;
}

interface CandidateRule {
  capability: string;
  effect: PolicyRuleEffect;
  agent_id?: string;
  active_window?: {
    start_hour?: number;
    end_hour?: number;
  };
  value?: unknown;
}

export function detectConflicts(
  candidate: CompiledPolicy,
  existing: PrincipalPolicyRule[],
): PolicyConflict[] {
  const normalizedCandidate = normalizeCandidate(candidate.compiled_rule);
  const conflicts: PolicyConflict[] = [];
  for (const rule of existing) {
    if (rule.capability !== normalizedCandidate.capability) continue;
    if (!sameOrOverlappingAgent(normalizedCandidate.agent_id, rule.agent_id)) {
      continue;
    }
    const exactTuple = sameAgent(normalizedCandidate.agent_id, rule.agent_id) &&
      sameWindow(normalizedCandidate.active_window, rule.active_window);
    const overlappingTuple = !exactTuple &&
      windowsOverlap(normalizedCandidate.active_window, rule.active_window);

    if (exactTuple && effectsContradict(normalizedCandidate.effect, rule.effect)) {
      conflicts.push(
        buildConflict(candidate, normalizedCandidate, rule, "contradiction"),
      );
      conflicts.push(
        buildConflict(candidate, normalizedCandidate, rule, "direct_override"),
      );
      continue;
    }

    if (exactTuple) {
      conflicts.push(
        buildConflict(candidate, normalizedCandidate, rule, "direct_override"),
      );
      continue;
    }

    if (overlappingTuple || valuesOverlap(normalizedCandidate.value, rule.value)) {
      conflicts.push(
        buildConflict(candidate, normalizedCandidate, rule, "partial_overlap"),
      );
    }
  }
  return conflicts;
}

export function principalPolicyToRules(policy: PrincipalPolicy): PrincipalPolicyRule[] {
  const rules: PrincipalPolicyRule[] = [];
  for (const op of policy.tier1_always_approve) {
    rules.push({
      rule_id: `tier1:${op}`,
      capability: op,
      effect: "deny",
      source: "tier1_always_approve",
      is_default: DEFAULT_POLICY.tier1_always_approve.includes(op),
    });
  }
  for (const op of policy.tier3_always_allow) {
    rules.push({
      rule_id: `tier3:${op}`,
      capability: op,
      effect: "allow",
      source: "tier3_always_allow",
      is_default: DEFAULT_POLICY.tier3_always_allow.includes(op),
    });
  }
  for (const field of Object.keys(policy.tier2_anomaly).sort() as Array<keyof Tier2Config>) {
    rules.push({
      rule_id: `tier2:${String(field)}`,
      capability: `tier2.${String(field)}`,
      effect: "set",
      source: "tier2_anomaly",
      value: policy.tier2_anomaly[field],
      is_default: policy.tier2_anomaly[field] === DEFAULT_POLICY.tier2_anomaly[field],
    });
  }
  return rules;
}

export function hasHighSeverityConflict(conflicts: PolicyConflict[]): boolean {
  return conflicts.some((c) => c.severity === "high");
}

export function conflictIds(conflicts: PolicyConflict[]): string[] {
  return conflicts.map((c) => c.conflict_id);
}

function normalizeCandidate(rule: CompiledPolicyRule): CandidateRule {
  switch (rule.kind) {
    case "tier1_add_operation":
      return withScope(rule, "deny");
    case "tier1_remove_operation":
      return withScope(rule, "allow");
    case "tier3_add_operation":
      return withScope(rule, "allow");
    case "tier3_remove_operation":
      return withScope(rule, "deny");
    case "tier2_set_field": {
      if (!rule.tier2_update) {
        return { capability: "tier2.unknown", effect: "set" };
      }
      return {
        capability: `tier2.${String(rule.tier2_update.field)}`,
        effect: "set",
        value: rule.tier2_update.value,
        ...(rule.bound_to_agent_id !== undefined
          ? { agent_id: rule.bound_to_agent_id }
          : {}),
        ...(rule.active_window !== undefined
          ? { active_window: rule.active_window }
          : {}),
      };
    }
    default: {
      const _exhaustive: never = rule.kind;
      return _exhaustive;
    }
  }
}

function withScope(rule: CompiledPolicyRule, effect: PolicyRuleEffect): CandidateRule {
  return {
    capability: rule.operation ?? "__missing_operation__",
    effect,
    ...(rule.bound_to_agent_id !== undefined
      ? { agent_id: rule.bound_to_agent_id }
      : {}),
    ...(rule.active_window !== undefined
      ? { active_window: rule.active_window }
      : {}),
  };
}

function buildConflict(
  candidatePolicy: CompiledPolicy,
  candidate: CandidateRule,
  existing: PrincipalPolicyRule,
  type: PolicyConflictType,
): PolicyConflict {
  const severity = severityFor(type, existing);
  const conflictId = [
    type,
    candidatePolicy.draft_id.slice(0, 12),
    existing.rule_id.replace(/[^a-zA-Z0-9_.:-]/g, "_"),
  ].join(":");
  return {
    conflict_id: conflictId,
    candidate_policy: candidatePolicy,
    existing_policy: existing,
    conflict_type: type,
    severity,
    explanation: explanationFor(type, candidate, existing, severity),
    affected_capability: existing.capability,
  };
}

function severityFor(
  type: PolicyConflictType,
  existing: PrincipalPolicyRule,
): PolicyConflictSeverity {
  if (type === "contradiction") return "high";
  if (type === "partial_overlap") return "medium";
  return existing.is_default === true ? "low" : "medium";
}

function explanationFor(
  type: PolicyConflictType,
  candidate: CandidateRule,
  existing: PrincipalPolicyRule,
  severity: PolicyConflictSeverity,
): string {
  const candidateAction = effectLabel(candidate.effect);
  const existingAction = effectLabel(existing.effect);
  if (type === "contradiction") {
    return `This policy would ${candidateAction} ${candidate.capability}, but active rule ${existing.rule_id} currently ${verbWithS(existingAction)} it. Activation is blocked until the operator acknowledges or forces the conflict.`;
  }
  if (type === "partial_overlap") {
    return `This policy overlaps active rule ${existing.rule_id} on ${candidate.capability}. Both rules can apply, so precedence may be ambiguous.`;
  }
  if (severity === "low") {
    return `This policy overrides default rule ${existing.rule_id} for ${candidate.capability}. This is expected when the operator intentionally replaces a shipped default.`;
  }
  return `This policy overrides active rule ${existing.rule_id} for ${candidate.capability}. Review the existing rule before activation.`;
}

function effectLabel(effect: PolicyRuleEffect): string {
  if (effect === "set") return "set";
  return effect;
}

function verbWithS(verb: string): string {
  if (verb === "deny") return "denies";
  if (verb === "set") return "sets";
  return `${verb}s`;
}

function effectsContradict(a: PolicyRuleEffect, b: PolicyRuleEffect): boolean {
  return (a === "allow" && b === "deny") || (a === "deny" && b === "allow");
}

function sameOrOverlappingAgent(a?: string, b?: string): boolean {
  return a === undefined || b === undefined || a === b;
}

function sameAgent(a?: string, b?: string): boolean {
  return (a ?? "*") === (b ?? "*");
}

function sameWindow(
  a?: PrincipalPolicyRule["active_window"],
  b?: PrincipalPolicyRule["active_window"],
): boolean {
  return (a?.start_hour ?? null) === (b?.start_hour ?? null) &&
    (a?.end_hour ?? null) === (b?.end_hour ?? null);
}

function windowsOverlap(
  a?: PrincipalPolicyRule["active_window"],
  b?: PrincipalPolicyRule["active_window"],
): boolean {
  if (a === undefined || b === undefined) return true;
  const aStart = a.start_hour ?? 0;
  const aEnd = a.end_hour ?? 24;
  const bStart = b.start_hour ?? 0;
  const bEnd = b.end_hour ?? 24;
  return aStart < bEnd && bStart < aEnd;
}

function valuesOverlap(a: unknown, b: unknown): boolean {
  if (a === undefined || b === undefined) return false;
  return a !== b;
}
