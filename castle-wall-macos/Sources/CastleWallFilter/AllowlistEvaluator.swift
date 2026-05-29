//
// AllowlistEvaluator.swift
//
// Pure flow evaluator. Given a `FilterFlowDescriptor` and a snapshot of
// the manifest's rules, returns an `EvaluationOutcome`.
//
// Disposition precedence (locked per spawn prompt's pre-baked
// architectural decisions):
//   1. If any rule with disposition `deny` matches the flow, drop with
//      that rule's id. Deny takes precedence over allow on overlap.
//   2. Otherwise, if any rule with disposition `allow` matches, allow
//      with that rule's id.
//   3. Otherwise, if any rule with disposition `prompt` matches, surface
//      as uncertain.
//   4. Otherwise, default-deny: drop with `nil` matched_rule_id.
//
// The evaluator is fully framework-free; it does not import
// NetworkExtension. Tests drive it directly against synthesized rule sets
// and descriptors.
//
// Source: Castle Wall Phase 1 Scope Lock 2026-05-03 section 4 (allowlist
// schema) + Castle Wall macOS Phase 1 packet filter spawn prompt
// (2026-05-11) verdict semantics.
//

import Foundation
import CastleWallIPC

public enum AllowlistEvaluator {

    /// The synthetic matched-rule id stamped on an operator-passthrough
    /// allow. Distinct from any real rule id so the audit log can tell an
    /// operator fast-path allow apart from a rule-matched allow, and so the
    /// legacy `"unknown"` templateId can never be confused with it.
    public static let operatorPassthroughRuleId = "operator_passthrough"

    /// Origin-gated evaluation (2026-05-29 fail-closed origin classifier).
    ///
    /// FAIL-CLOSED INVARIANT: ONLY a `.operator` classification earns the
    /// allow fast-path. `.agent` AND `.unattributed` BOTH fall through to the
    /// existing default-deny + allowlist path. There is NO code path here
    /// where "could not determine origin" (`.unattributed`) reaches
    /// operator-allow.
    public static func evaluate(
        flow: FilterFlowDescriptor,
        rules: [ManifestRule],
        agentOrigin: AgentOriginDescriptor?
    ) -> EvaluationOutcome {
        let origin = OriginClassifier.originClass(
            descriptor: flow,
            agentOrigin: agentOrigin
        )

        // Operator fast-path: ONLY a POSITIVE operator determination passes
        // here. This gate sits BEFORE the rule loop. `.agent` and
        // `.unattributed` deliberately do NOT take it.
        if origin == .operator {
            return .allow(matchedRuleId: operatorPassthroughRuleId)
        }

        // `.agent` and `.unattributed` route to the unchanged default-deny +
        // allowlist evaluation. Default-deny on no match is preserved.
        return evaluate(flow: flow, rules: rules)
    }

    /// Evaluate a flow against the current manifest snapshot.
    public static func evaluate(
        flow: FilterFlowDescriptor,
        rules: [ManifestRule]
    ) -> EvaluationOutcome {
        var firstAllow: ManifestRule?
        var firstPrompt: ManifestRule?

        for rule in rules where matches(rule: rule, flow: flow) {
            switch rule.disposition {
            case "deny":
                return .drop(matchedRuleId: rule.id)
            case "allow":
                if firstAllow == nil { firstAllow = rule }
            case "prompt":
                if firstPrompt == nil { firstPrompt = rule }
            default:
                continue
            }
        }

        if let allow = firstAllow {
            return .allow(matchedRuleId: allow.id)
        }
        if firstPrompt != nil {
            return .uncertain
        }
        return .drop(matchedRuleId: nil)
    }

    /// True when the rule's match conditions and scope both apply to the flow.
    public static func matches(rule: ManifestRule, flow: FilterFlowDescriptor) -> Bool {
        if !scopeMatches(scope: rule.scope, flow: flow) {
            return false
        }
        return matchClauseMatches(match: rule.match, flow: flow)
    }

    /// Scope: agent_ids OR template_ids. Empty/nil on both means "all".
    public static func scopeMatches(scope: ManifestRuleScope, flow: FilterFlowDescriptor) -> Bool {
        let hasAgents = scope.agentIds?.isEmpty == false
        let hasTemplates = scope.templateIds?.isEmpty == false
        if !hasAgents && !hasTemplates {
            return true
        }
        if hasAgents, let agents = scope.agentIds, agents.contains(flow.agentId) {
            return true
        }
        if hasTemplates, let templates = scope.templateIds, templates.contains(flow.templateId) {
            return true
        }
        return false
    }

    /// Match clause: at least one of host, host_pattern, or port must be
    /// specified at validation time (the runtime side rejects malformed
    /// rules before they reach the extension). Each unspecified field is
    /// "match any". Protocol filter is enforced when present.
    public static func matchClauseMatches(match: ManifestRuleMatch, flow: FilterFlowDescriptor) -> Bool {
        if let proto = match.protocolName, !protocolMatches(spec: proto, flow: flow) {
            return false
        }

        if let port = match.port, !portMatches(spec: port, flow: flow) {
            return false
        }

        let hasExactHost = match.host != nil
        let hasHostPattern = match.hostPattern?.isEmpty == false
        if hasExactHost || hasHostPattern {
            var hostAxisMatches = false
            if let host = match.host, hostMatches(spec: host, flow: flow) {
                hostAxisMatches = true
            }
            if let pattern = match.hostPattern, hostPatternMatches(pattern: pattern, flow: flow) {
                hostAxisMatches = true
            }
            if !hostAxisMatches {
                return false
            }
        }

        return true
    }

    static func protocolMatches(spec: String, flow: FilterFlowDescriptor) -> Bool {
        switch spec {
        case "tcp": return flow.networkProtocol == .tcp
        case "udp": return flow.networkProtocol == .udp
        case "tcp+udp": return true
        default: return false
        }
    }

    static func portMatches(spec: ManifestRulePortMatch, flow: FilterFlowDescriptor) -> Bool {
        return spec.values.contains(flow.destinationPort)
    }

    static func hostMatches(spec: ManifestRuleHostMatch, flow: FilterFlowDescriptor) -> Bool {
        guard let host = flow.destinationHost else { return false }
        return spec.values.contains { candidate in
            candidate.caseInsensitiveCompare(host) == .orderedSame
        }
    }

    /// Host-pattern: simple suffix wildcard (`*.example.com`) and exact
    /// patterns. Phase 1 keeps grammar minimal; richer patterns land in
    /// v1.x once the operator-UX surface is locked.
    static func hostPatternMatches(pattern: String, flow: FilterFlowDescriptor) -> Bool {
        guard let host = flow.destinationHost else { return false }
        if pattern.hasPrefix("*.") {
            let suffix = String(pattern.dropFirst(2))
            if suffix.isEmpty {
                return false
            }
            let hostLower = host.lowercased()
            let suffixLower = suffix.lowercased()
            return hostLower.hasSuffix("." + suffixLower)
                && hostLower != suffixLower
        }
        return host.caseInsensitiveCompare(pattern) == .orderedSame
    }
}
