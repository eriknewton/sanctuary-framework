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
#if canImport(Darwin)
import Darwin
#endif
import CastleWallIPC

public enum AllowlistEvaluator {

    /// The synthetic matched-rule id stamped on non-agent UID baseline allows.
    /// Distinct from real policy rule ids so the audit log can distinguish
    /// operator/system baseline traffic from rule-matched agent traffic.
    public static let operatorBaselineUidRuleId = "operator-baseline-uid"

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
        agentOrigin: AgentOriginDescriptor?,
        operatorBaseline: OperatorBaselineWire? = nil
    ) -> EvaluationOutcome {
        let origin = OriginClassifier.originClass(
            descriptor: flow,
            agentOrigin: agentOrigin
        )

        // Operator fast-path: ONLY a POSITIVE operator determination passes
        // here. This gate sits BEFORE the rule loop. `.agent` and
        // `.unattributed` deliberately do NOT take it.
        if origin == .operator {
            return .allow(matchedRuleId: baselineRuleId(flow: flow, operatorBaseline: operatorBaseline))
        }

        // HIGH-1 hardening (confined-agent egress design 2026-07-10,
        // adversarial-review must-fix, then PR-905-review BLOCKER fix): when a
        // flow is `.unattributed` it is the FAIL-CLOSED bucket and must NEVER
        // earn an allow-disposition match, UNLESS we POSITIVELY know we are in
        // NAT mode (where `.unattributed` flows are common unsigned
        // operator-software and the documented NAT rationale keeps the allow).
        // Publishing unscoped agent allow rules (the egress provisioning
        // build) would otherwise invert this bucket to fail-OPEN for
        // exfil-capable hosts -- any flow whose audit token fails to decode
        // would inherit the agent's grants.
        //
        // The predicate is `agentOrigin?.mode != .nat`, NOT `== .uid`: the
        // `== .uid` form failed OPEN when `agentOrigin == nil` (nil?.mode is
        // nil, nil != .uid), and a nil descriptor is REACHABLE -- provisioned
        // allow rules and the origin descriptor install non-atomically (the
        // rules go live via `store.update` before `installAgentOriginIfPresent`
        // runs), so on every manifest apply / recovery there is a window where
        // allow rules are live while the engine's retained `_agentOrigin` is
        // still nil (FlowEvaluatorEngine). The `!= .nat` form suppresses for
        // the nil-descriptor AND uid-mode cases (both fail closed) and keeps
        // the allow ONLY for a positively-resolved NAT mode. The install
        // ordering is ALSO reordered (installAgentOriginIfPresent BEFORE
        // store.update) to close the window structurally as defense in depth;
        // this predicate is the invariant that holds regardless of ordering.
        // Deny rules keep applying and prompt rules keep surfacing for
        // operator decision; the bucket simply stops benefiting from allows.
        // No wire or schema change.
        let suppressAllowMatches = origin == .unattributed && agentOrigin?.mode != .nat

        // `.agent` and `.unattributed` route to the unchanged default-deny +
        // allowlist evaluation. Default-deny on no match is preserved.
        return evaluate(flow: flow, rules: rules, suppressAllowMatches: suppressAllowMatches)
    }

    static func baselineRuleId(
        flow: FilterFlowDescriptor,
        operatorBaseline: OperatorBaselineWire?
    ) -> String {
        if let essential = matchingEssential(flow: flow, operatorBaseline: operatorBaseline) {
            return "essentials-\(essential.name)"
        }
        return operatorBaselineUidRuleId
    }

    static func matchingEssential(
        flow: FilterFlowDescriptor,
        operatorBaseline: OperatorBaselineWire?
    ) -> OperatorBaselineEssentialWire? {
        guard let operatorBaseline else { return nil }
        return operatorBaseline.essentials.first { entry in
            if let signingId = entry.signingId, signingId != flow.sourceSigningId {
                return false
            }
            if let teamId = entry.teamId, teamId != flow.sourceTeamId {
                return false
            }
            if let sourceAppIdentifier = entry.sourceAppIdentifier,
               sourceAppIdentifier != flow.sourceAppIdentifier {
                return false
            }
            return entry.signingId != nil || entry.teamId != nil || entry.sourceAppIdentifier != nil
        }
    }

    /// Evaluate a flow against the current manifest snapshot.
    ///
    /// `suppressAllowMatches` (HIGH-1 hardening, default `false` so every
    /// existing caller is unchanged): when `true`, allow-disposition rules
    /// never match-through -- deny rules keep applying, prompt rules keep
    /// surfacing, and the default-deny floor is preserved. Set ONLY for
    /// uid-mode `.unattributed` flows by the origin-gated overload above.
    public static func evaluate(
        flow: FilterFlowDescriptor,
        rules: [ManifestRule],
        suppressAllowMatches: Bool = false
    ) -> EvaluationOutcome {
        var firstAllow: ManifestRule?
        var firstPrompt: ManifestRule?

        for rule in rules where matches(rule: rule, flow: flow) {
            switch rule.disposition {
            case "deny":
                return .drop(matchedRuleId: rule.id)
            case "allow":
                if !suppressAllowMatches, firstAllow == nil { firstAllow = rule }
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

        // Destination axes (host / host_pattern / ip / cidr) compose as an OR:
        // when none is specified the destination is "match any"; when one or
        // more are specified, at least one must match. This must agree with the
        // TS evaluator (egress-proxy) on every input.
        let hasExactHost = match.host != nil
        let hasHostPattern = match.hostPattern?.isEmpty == false
        let hasIp = match.ip != nil
        let hasCidr = match.cidr != nil
        if hasExactHost || hasHostPattern || hasIp || hasCidr {
            var destinationMatches = false
            if let host = match.host, hostMatches(spec: host, flow: flow) {
                destinationMatches = true
            }
            if let pattern = match.hostPattern, hostPatternMatches(pattern: pattern, flow: flow) {
                destinationMatches = true
            }
            if let ip = match.ip, ipMatches(spec: ip, flow: flow) {
                destinationMatches = true
            }
            if let cidr = match.cidr, cidrMatches(spec: cidr, flow: flow) {
                destinationMatches = true
            }
            if !destinationMatches {
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

    // MARK: - IP / CIDR matching (#380)
    //
    // A parsed IP address: its family (AF_INET / AF_INET6) and its address bytes
    // in network order (4 bytes for IPv4, 16 for IPv6). Equality and CIDR
    // containment operate on these normalized bytes so textual variants
    // (`::1` vs `0:0:0:0:0:0:0:1`, zero-padding) compare equal, and a mismatched
    // family never matches. This must agree with the TS evaluator on every input.

    struct ParsedIP: Equatable {
        let family: Int32
        let bytes: [UInt8]
    }

    /// Parse an IPv4 or IPv6 literal to normalized network-order bytes via
    /// `inet_pton`, or nil when the string is not a valid IP of either family.
    static func parseIP(_ text: String) -> ParsedIP? {
        var v4 = in_addr()
        if inet_pton(AF_INET, text, &v4) == 1 {
            var bytes = [UInt8](repeating: 0, count: 4)
            withUnsafeBytes(of: &v4.s_addr) { raw in
                for i in 0..<4 { bytes[i] = raw[i] }
            }
            return ParsedIP(family: AF_INET, bytes: bytes)
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, text, &v6) == 1 {
            var bytes = [UInt8](repeating: 0, count: 16)
            withUnsafeBytes(of: &v6) { raw in
                for i in 0..<16 { bytes[i] = raw[i] }
            }
            return ParsedIP(family: AF_INET6, bytes: bytes)
        }
        return nil
    }

    /// True iff the flow's destination IP exactly equals any IP in `spec`
    /// (family-aware). Malformed candidate strings never match.
    static func ipMatches(spec: ManifestRuleHostMatch, flow: FilterFlowDescriptor) -> Bool {
        guard let target = parseIP(flow.destinationIp) else { return false }
        return spec.values.contains { candidate in
            guard let parsed = parseIP(candidate) else { return false }
            return parsed.family == target.family && parsed.bytes == target.bytes
        }
    }

    /// True iff the flow's destination IP falls inside any CIDR in `spec`
    /// (family-aware prefix containment). Malformed candidates never match.
    static func cidrMatches(spec: ManifestRuleHostMatch, flow: FilterFlowDescriptor) -> Bool {
        guard let target = parseIP(flow.destinationIp) else { return false }
        return spec.values.contains { cidr in
            cidrContains(cidr: cidr, ip: target)
        }
    }

    /// True iff `ip` is contained in `cidr` (`addr/prefix`). Rejects a missing
    /// or non-numeric prefix, an out-of-range prefix, an unparseable base, or a
    /// family mismatch between base and `ip`.
    static func cidrContains(cidr: String, ip: ParsedIP) -> Bool {
        let parts = cidr.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2, let prefix = Int(parts[1]) else { return false }
        guard let base = parseIP(String(parts[0])) else { return false }
        guard base.family == ip.family else { return false }
        let maxBits = base.family == AF_INET ? 32 : 128
        guard prefix >= 0 && prefix <= maxBits else { return false }
        return prefixBitsEqual(base.bytes, ip.bytes, prefixBits: prefix)
    }

    /// True iff the first `prefixBits` bits of `a` and `b` are equal. Both byte
    /// arrays are assumed the same length (same family).
    static func prefixBitsEqual(_ a: [UInt8], _ b: [UInt8], prefixBits: Int) -> Bool {
        let fullBytes = prefixBits / 8
        let remainderBits = prefixBits % 8
        for i in 0..<fullBytes where a[i] != b[i] {
            return false
        }
        if remainderBits > 0 {
            let mask = UInt8(truncatingIfNeeded: 0xFF << (8 - remainderBits))
            if (a[fullBytes] & mask) != (b[fullBytes] & mask) {
                return false
            }
        }
        return true
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
