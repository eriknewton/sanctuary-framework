//
// AllowlistEvaluatorTests.swift
//
// Pure-logic tests for the manifest evaluator. No NetworkExtension
// dependency. Drives the evaluator against synthesized rule sets and
// flow descriptors; asserts the disposition precedence rules and the
// match-clause / scope semantics.
//

import XCTest
@testable import CastleWallFilter
import CastleWallIPC

final class AllowlistEvaluatorTests: XCTestCase {

    // MARK: - Helpers

    func rule(
        id: String = "r-1",
        host: ManifestRuleHostMatch? = nil,
        hostPattern: String? = nil,
        ip: ManifestRuleHostMatch? = nil,
        cidr: ManifestRuleHostMatch? = nil,
        port: ManifestRulePortMatch? = nil,
        protocolName: String? = nil,
        agentIds: [String]? = nil,
        templateIds: [String]? = nil,
        disposition: String = "allow"
    ) -> ManifestRule {
        return ManifestRule(
            id: id,
            schemaVersion: 1,
            createdAt: "2026-05-11T00:00:00Z",
            description: nil,
            match: ManifestRuleMatch(
                host: host,
                hostPattern: hostPattern,
                ip: ip,
                cidr: cidr,
                port: port,
                protocolName: protocolName
            ),
            scope: ManifestRuleScope(agentIds: agentIds, templateIds: templateIds),
            disposition: disposition,
            timeWindow: nil
        )
    }

    func flow(
        agentId: String = "agent-7",
        templateId: String = "coding-assistant",
        host: String? = "api.anthropic.com",
        ip: String = "104.18.32.10",
        port: Int = 443,
        proto: FlowProtocol = .tcp
    ) -> FilterFlowDescriptor {
        return FilterFlowDescriptor(
            sourceAppIdentifier: "ai.sanctuaryprotocol.test",
            agentId: agentId,
            templateId: templateId,
            destinationHost: host,
            destinationIp: ip,
            destinationPort: port,
            networkProtocol: proto,
            hostnameSource: host != nil ? "sni" : nil,
            opaqueDestination: host == nil
        )
    }

    // MARK: - Disposition precedence

    func testExactHostAllowMatches() {
        let r = rule(host: .single("api.anthropic.com"), port: .single(443), protocolName: "tcp", disposition: "allow")
        let outcome = AllowlistEvaluator.evaluate(flow: flow(), rules: [r])
        XCTAssertEqual(outcome, .allow(matchedRuleId: "r-1"))
    }

    func testHostMismatchFallsThroughToDefaultDeny() {
        let r = rule(host: .single("api.openai.com"), port: .single(443), protocolName: "tcp", disposition: "allow")
        let outcome = AllowlistEvaluator.evaluate(flow: flow(), rules: [r])
        XCTAssertEqual(outcome, .drop(matchedRuleId: nil))
    }

    func testDenyTakesPrecedenceOverAllow() {
        let allowRule = rule(id: "allow-1", host: .single("api.anthropic.com"), port: .single(443), disposition: "allow")
        let denyRule = rule(id: "deny-1", host: .single("api.anthropic.com"), port: .single(443), disposition: "deny")
        let outcome = AllowlistEvaluator.evaluate(flow: flow(), rules: [allowRule, denyRule])
        XCTAssertEqual(outcome, .drop(matchedRuleId: "deny-1"))
    }

    func testPromptSurfacesWhenNoAllowOrDenyMatches() {
        let promptRule = rule(id: "prompt-1", host: .single("api.anthropic.com"), disposition: "prompt")
        let outcome = AllowlistEvaluator.evaluate(flow: flow(), rules: [promptRule])
        XCTAssertEqual(outcome, .uncertain)
    }

    func testAllowBeatsPromptOnOverlap() {
        let allowRule = rule(id: "allow-1", host: .single("api.anthropic.com"), disposition: "allow")
        let promptRule = rule(id: "prompt-1", host: .single("api.anthropic.com"), disposition: "prompt")
        let outcome = AllowlistEvaluator.evaluate(flow: flow(), rules: [promptRule, allowRule])
        XCTAssertEqual(outcome, .allow(matchedRuleId: "allow-1"))
    }

    func testEmptyRuleSetIsDefaultDeny() {
        let outcome = AllowlistEvaluator.evaluate(flow: flow(), rules: [])
        XCTAssertEqual(outcome, .drop(matchedRuleId: nil))
    }

    // MARK: - Match clause

    func testHostArrayMatchesAnyMember() {
        let r = rule(host: .multiple(["api.openai.com", "api.anthropic.com"]), disposition: "allow")
        XCTAssertEqual(AllowlistEvaluator.evaluate(flow: flow(), rules: [r]), .allow(matchedRuleId: "r-1"))
    }

    func testHostMatchIsCaseInsensitive() {
        let r = rule(host: .single("API.ANTHROPIC.COM"), disposition: "allow")
        XCTAssertEqual(AllowlistEvaluator.evaluate(flow: flow(), rules: [r]), .allow(matchedRuleId: "r-1"))
    }

    func testHostPatternSuffixWildcardMatches() {
        let r = rule(hostPattern: "*.anthropic.com", disposition: "allow")
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(host: "api.anthropic.com"), rules: [r]),
            .allow(matchedRuleId: "r-1")
        )
    }

    func testHostPatternRequiresDotBoundary() {
        let r = rule(hostPattern: "*.anthropic.com", disposition: "allow")
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(host: "evil-anthropic.com"), rules: [r]),
            .drop(matchedRuleId: nil)
        )
    }

    func testHostPatternRejectsBareSuffixMatch() {
        // `*.anthropic.com` should match `foo.anthropic.com` but NOT
        // `anthropic.com` itself.
        let r = rule(hostPattern: "*.anthropic.com", disposition: "allow")
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(host: "anthropic.com"), rules: [r]),
            .drop(matchedRuleId: nil)
        )
    }

    func testExactHostOrHostPatternMatchWhenBothPresent() {
        let r = rule(
            host: .single("api.anthropic.com"),
            hostPattern: "*.anthropic.com",
            disposition: "allow"
        )
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(host: "api.anthropic.com"), rules: [r]),
            .allow(matchedRuleId: "r-1")
        )
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(host: "console.anthropic.com"), rules: [r]),
            .allow(matchedRuleId: "r-1")
        )
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(host: "evil-anthropic.com"), rules: [r]),
            .drop(matchedRuleId: nil)
        )
    }

    func testPortArrayMatchesAnyMember() {
        let r = rule(host: .single("api.anthropic.com"), port: .multiple([80, 443]), disposition: "allow")
        XCTAssertEqual(AllowlistEvaluator.evaluate(flow: flow(port: 443), rules: [r]), .allow(matchedRuleId: "r-1"))
        XCTAssertEqual(AllowlistEvaluator.evaluate(flow: flow(port: 80), rules: [r]), .allow(matchedRuleId: "r-1"))
        XCTAssertEqual(AllowlistEvaluator.evaluate(flow: flow(port: 8080), rules: [r]), .drop(matchedRuleId: nil))
    }

    func testProtocolFilterTcpUdp() {
        let tcpRule = rule(id: "tcp-1", host: .single("api.anthropic.com"), protocolName: "tcp", disposition: "allow")
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(proto: .tcp), rules: [tcpRule]),
            .allow(matchedRuleId: "tcp-1")
        )
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(proto: .udp), rules: [tcpRule]),
            .drop(matchedRuleId: nil)
        )

        let bothRule = rule(id: "both-1", host: .single("api.anthropic.com"), protocolName: "tcp+udp", disposition: "allow")
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(proto: .tcp), rules: [bothRule]),
            .allow(matchedRuleId: "both-1")
        )
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(proto: .udp), rules: [bothRule]),
            .allow(matchedRuleId: "both-1")
        )
    }

    // MARK: - IP / CIDR match clause (#380)

    func testExactIpv4Matches() {
        let r = rule(ip: .single("1.1.1.1"), port: .single(53), protocolName: "tcp+udp", disposition: "allow")
        let f = flow(host: nil, ip: "1.1.1.1", port: 53, proto: .udp)
        XCTAssertEqual(AllowlistEvaluator.evaluate(flow: f, rules: [r]), .allow(matchedRuleId: "r-1"))
    }

    func testExactIpv4NonResolverDoesNotMatch() {
        // THE security property: a port-53 flow to a NON-resolver IP must not
        // match an ip-scoped DNS allow (no tunneling to an arbitrary server).
        let r = rule(ip: .multiple(["1.1.1.1", "8.8.8.8"]), port: .single(53), protocolName: "tcp+udp", disposition: "allow")
        let f = flow(host: nil, ip: "9.9.9.9", port: 53, proto: .udp)
        XCTAssertEqual(AllowlistEvaluator.evaluate(flow: f, rules: [r]), .drop(matchedRuleId: nil))
    }

    func testIpArrayMatchesAnyMember() {
        let r = rule(ip: .multiple(["1.1.1.1", "8.8.8.8"]), disposition: "allow")
        let f = flow(host: nil, ip: "8.8.8.8")
        XCTAssertEqual(AllowlistEvaluator.evaluate(flow: f, rules: [r]), .allow(matchedRuleId: "r-1"))
    }

    func testExactIpv6MatchesAcrossTextualForms() {
        // `::1` normalized equals the fully-expanded form.
        let r = rule(ip: .single("0:0:0:0:0:0:0:1"), disposition: "allow")
        let f = flow(host: nil, ip: "::1")
        XCTAssertEqual(AllowlistEvaluator.evaluate(flow: f, rules: [r]), .allow(matchedRuleId: "r-1"))
    }

    func testIpv4DoesNotMatchIpv6Family() {
        let r = rule(ip: .single("1.1.1.1"), disposition: "allow")
        let f = flow(host: nil, ip: "::1")
        XCTAssertEqual(AllowlistEvaluator.evaluate(flow: f, rules: [r]), .drop(matchedRuleId: nil))
    }

    func testCidrIpv4Contains() {
        let r = rule(cidr: .single("10.0.0.0/24"), disposition: "allow")
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(host: nil, ip: "10.0.0.1"), rules: [r]),
            .allow(matchedRuleId: "r-1")
        )
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(host: nil, ip: "10.0.0.255"), rules: [r]),
            .allow(matchedRuleId: "r-1")
        )
    }

    func testCidrIpv4BoundaryOutsideDoesNotMatch() {
        let r = rule(cidr: .single("10.0.0.0/24"), disposition: "allow")
        // network base of the NEXT block and the last address of the PREVIOUS block
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(host: nil, ip: "10.0.1.0"), rules: [r]),
            .drop(matchedRuleId: nil)
        )
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(host: nil, ip: "9.255.255.255"), rules: [r]),
            .drop(matchedRuleId: nil)
        )
    }

    func testCidrSlash32ExactHostOnly() {
        let r = rule(cidr: .single("203.0.113.7/32"), disposition: "allow")
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(host: nil, ip: "203.0.113.7"), rules: [r]),
            .allow(matchedRuleId: "r-1")
        )
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(host: nil, ip: "203.0.113.8"), rules: [r]),
            .drop(matchedRuleId: nil)
        )
    }

    func testCidrIpv6Slash128ExactHostOnly() {
        let r = rule(cidr: .single("2001:db8::1/128"), disposition: "allow")
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(host: nil, ip: "2001:db8::1"), rules: [r]),
            .allow(matchedRuleId: "r-1")
        )
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(host: nil, ip: "2001:db8::2"), rules: [r]),
            .drop(matchedRuleId: nil)
        )
    }

    func testCidrIpv6PrefixContains() {
        let r = rule(cidr: .single("2001:db8::/32"), disposition: "allow")
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(host: nil, ip: "2001:db8:dead:beef::1"), rules: [r]),
            .allow(matchedRuleId: "r-1")
        )
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(host: nil, ip: "2001:db9::1"), rules: [r]),
            .drop(matchedRuleId: nil)
        )
    }

    func testCidrMismatchedFamilyNeverMatches() {
        let r = rule(cidr: .single("10.0.0.0/8"), disposition: "allow")
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(host: nil, ip: "::1"), rules: [r]),
            .drop(matchedRuleId: nil)
        )
    }

    func testMalformedCidrPrefixNeverMatches() {
        // A /33 (IPv4) is out of range; must never match (and never crash).
        let r = rule(cidr: .single("10.0.0.0/33"), disposition: "allow")
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(host: nil, ip: "10.0.0.1"), rules: [r]),
            .drop(matchedRuleId: nil)
        )
    }

    func testIpAndPortCompose_derivedDnsShape() {
        // The exact shape of the derived DNS rule: ip-scoped + port 53 + tcp+udp.
        let r = rule(
            id: "derived_dns_for_hostname_rules",
            ip: .multiple(["1.1.1.1", "8.8.8.8"]),
            port: .single(53),
            protocolName: "tcp+udp",
            disposition: "allow"
        )
        // resolver + port 53 over UDP -> allow
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(host: nil, ip: "1.1.1.1", port: 53, proto: .udp), rules: [r]),
            .allow(matchedRuleId: "derived_dns_for_hostname_rules")
        )
        // resolver IP but a NON-53 port -> no match (port axis constrains)
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(host: nil, ip: "1.1.1.1", port: 443, proto: .tcp), rules: [r]),
            .drop(matchedRuleId: nil)
        )
        // port 53 to a non-resolver -> no match (ip axis constrains)
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(host: nil, ip: "9.9.9.9", port: 53, proto: .udp), rules: [r]),
            .drop(matchedRuleId: nil)
        )
    }

    // MARK: - Scope

    func testScopeAgentIdsConstrainsRule() {
        let r = rule(host: .single("api.anthropic.com"), agentIds: ["agent-7"], disposition: "allow")
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(agentId: "agent-7"), rules: [r]),
            .allow(matchedRuleId: "r-1")
        )
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(agentId: "agent-other"), rules: [r]),
            .drop(matchedRuleId: nil)
        )
    }

    func testScopeTemplateIdsConstrainsRule() {
        let r = rule(host: .single("api.anthropic.com"), templateIds: ["coding-assistant"], disposition: "allow")
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(templateId: "coding-assistant"), rules: [r]),
            .allow(matchedRuleId: "r-1")
        )
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(templateId: "ops-runner"), rules: [r]),
            .drop(matchedRuleId: nil)
        )
    }

    func testScopeMatchesEitherAgentsOrTemplates() {
        let r = rule(
            host: .single("api.anthropic.com"),
            agentIds: ["specific-agent"],
            templateIds: ["coding-assistant"],
            disposition: "allow"
        )
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(
                flow: flow(agentId: "different-agent", templateId: "coding-assistant"),
                rules: [r]
            ),
            .allow(matchedRuleId: "r-1")
        )
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(
                flow: flow(agentId: "specific-agent", templateId: "different-template"),
                rules: [r]
            ),
            .allow(matchedRuleId: "r-1")
        )
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(
                flow: flow(agentId: "different-agent", templateId: "different-template"),
                rules: [r]
            ),
            .drop(matchedRuleId: nil)
        )
    }

    func testEmptyScopeMeansAllAgents() {
        let r = rule(host: .single("api.anthropic.com"), agentIds: nil, templateIds: nil, disposition: "allow")
        XCTAssertEqual(
            AllowlistEvaluator.evaluate(flow: flow(agentId: "any-agent", templateId: "any-template"), rules: [r]),
            .allow(matchedRuleId: "r-1")
        )
    }

    // MARK: - Origin-gated evaluation (2026-05-29 fail-closed classifier)
    //
    // These exercise the additive `evaluate(flow:rules:agentOrigin:)` path.
    // The single thing under test: ONLY `.operator` earns the allow
    // fast-path; `.agent` and `.unattributed` fall through to default-deny +
    // allowlist.

    /// Attributed descriptor with the given ruid/signing identity.
    private func originFlow(
        ruid: uid_t = 501,
        signingId: String? = nil,
        teamId: String? = nil,
        host: String? = "api.anthropic.com",
        port: Int = 443,
        unattributed: Bool = false
    ) -> FilterFlowDescriptor {
        return FilterFlowDescriptor(
            sourceAppIdentifier: "deadbeef",
            agentId: "deadbeef",
            templateId: "unknown",
            destinationHost: host,
            destinationIp: "104.18.32.10",
            destinationPort: port,
            networkProtocol: .tcp,
            hostnameSource: host != nil ? "sni" : nil,
            opaqueDestination: host == nil,
            sourceRuid: ruid,
            sourcePid: 4242,
            sourcePidVersion: 1,
            sourceSigningId: signingId,
            sourceTeamId: teamId,
            sourceUnattributed: unattributed
        )
    }

    private func uidOrigin() -> AgentOriginDescriptor {
        return AgentOriginDescriptor(mode: .uid, agentUid: 600, systemUidAllowCeiling: 500)
    }

    private func natOrigin() -> AgentOriginDescriptor {
        return AgentOriginDescriptor(
            mode: .nat,
            egressHelperSigningId: "ai.sanctuaryprotocol.egress-helper",
            systemUidAllowCeiling: 500
        )
    }

    // UID mode

    func testUidMode_agentFlowNonAllowlistedDrops() {
        // agent-UID flow, no matching rule => default-deny (NOT operator).
        let outcome = AllowlistEvaluator.evaluate(
            flow: originFlow(ruid: 600),
            rules: [],
            agentOrigin: uidOrigin()
        )
        XCTAssertEqual(outcome, .drop(matchedRuleId: nil))
    }

    func testUidMode_agentFlowAllowlistedAllowsWithRuleId() {
        let r = rule(host: .single("api.anthropic.com"), disposition: "allow")
        let outcome = AllowlistEvaluator.evaluate(
            flow: originFlow(ruid: 600),
            rules: [r],
            agentOrigin: uidOrigin()
        )
        // Rule-matched allow, NOT operator-baseline.
        XCTAssertEqual(outcome, .allow(matchedRuleId: "r-1"))
    }

    func testUidMode_operatorFlowFastPathAllows() {
        // operator-UID (high uid != agent) => operator-baseline, even with
        // an empty ruleset that would otherwise default-deny.
        let outcome = AllowlistEvaluator.evaluate(
            flow: originFlow(ruid: 501),
            rules: [],
            agentOrigin: uidOrigin()
        )
        XCTAssertEqual(outcome, .allow(matchedRuleId: AllowlistEvaluator.operatorBaselineUidRuleId))
    }

    func testUidMode_systemLowUidFastPathAllows() {
        let outcome = AllowlistEvaluator.evaluate(
            flow: originFlow(ruid: 1),
            rules: [],
            agentOrigin: uidOrigin()
        )
        XCTAssertEqual(outcome, .allow(matchedRuleId: AllowlistEvaluator.operatorBaselineUidRuleId))
    }

    func testUidMode_systemEssentialUsesNamedBaselineRuleId() {
        let baseline = OperatorBaselineWire(essentials: [
            OperatorBaselineEssentialWire(
                name: "tailscaled",
                signingId: "com.tailscale.ipn.macos.network-extension"
            )
        ])
        let outcome = AllowlistEvaluator.evaluate(
            flow: originFlow(ruid: 0, signingId: "com.tailscale.ipn.macos.network-extension"),
            rules: [],
            agentOrigin: uidOrigin(),
            operatorBaseline: baseline
        )
        XCTAssertEqual(outcome, .allow(matchedRuleId: "essentials-tailscaled"))
    }

    func testUidMode_agentUidCannotRideBaselineEvenWhenEssentialMatches() {
        let baseline = OperatorBaselineWire(essentials: [
            OperatorBaselineEssentialWire(
                name: "curl",
                sourceAppIdentifier: "deadbeef"
            )
        ])
        let outcome = AllowlistEvaluator.evaluate(
            flow: originFlow(ruid: 502),
            rules: [],
            agentOrigin: AgentOriginDescriptor(mode: .uid, agentUid: 502, systemUidAllowCeiling: 500),
            operatorBaseline: baseline
        )
        XCTAssertEqual(outcome, .drop(matchedRuleId: nil))
    }

    func testUidMode_unattributedDropsFailClosed() {
        // Undecodable token => unattributed => deny side, even though its
        // (meaningless) ruid value would be a system/operator uid.
        let outcome = AllowlistEvaluator.evaluate(
            flow: originFlow(ruid: 0, unattributed: true),
            rules: [],
            agentOrigin: uidOrigin()
        )
        XCTAssertEqual(outcome, .drop(matchedRuleId: nil))
    }

    // MARK: - HIGH-1 hardening (confined-agent egress design 2026-07-10):
    // in UID mode, `.unattributed` NEVER earns an allow-disposition match.
    // The egress provisioning build publishes UNSCOPED agent allow rules;
    // without this clause every audit-token decode failure would inherit
    // those grants (fail-closed bucket inverted to fail-open). This is the
    // drill's Leg-1 check-3 control, proven here at the unit level.

    func testHigh1_uidMode_unattributedNeverEarnsAllowMatch() {
        // An UNSCOPED allow rule that MATCHES the flow's host: the exact
        // shape the egress provisioning publishes. Before the hardening this
        // evaluated .allow("r-1") for an unattributed flow.
        let r = rule(host: .single("api.anthropic.com"), disposition: "allow")
        let outcome = AllowlistEvaluator.evaluate(
            flow: originFlow(ruid: 0, unattributed: true),
            rules: [r],
            agentOrigin: uidOrigin()
        )
        XCTAssertEqual(outcome, .drop(matchedRuleId: nil))
    }

    func testHigh1_uidMode_agentStillEarnsTheSameAllowMatch() {
        // Control: the SAME rule set still grants the positively-classified
        // agent flow (the hardening suppresses allows for `.unattributed`
        // only, never for `.agent`).
        let r = rule(host: .single("api.anthropic.com"), disposition: "allow")
        let outcome = AllowlistEvaluator.evaluate(
            flow: originFlow(ruid: 600),
            rules: [r],
            agentOrigin: uidOrigin()
        )
        XCTAssertEqual(outcome, .allow(matchedRuleId: "r-1"))
    }

    func testHigh1_uidMode_unattributedDenyRulesStillApply() {
        // Deny rules keep applying to the fail-closed bucket (the hardening
        // removes a benefit, never a restriction).
        let r = rule(host: .single("api.anthropic.com"), disposition: "deny")
        let outcome = AllowlistEvaluator.evaluate(
            flow: originFlow(ruid: 0, unattributed: true),
            rules: [r],
            agentOrigin: uidOrigin()
        )
        XCTAssertEqual(outcome, .drop(matchedRuleId: "r-1"))
    }

    func testHigh1_uidMode_unattributedPromptRulesStillSurface() {
        // Prompt rules keep surfacing for an operator decision (a human
        // gate, not a silent allow).
        let r = rule(host: .single("api.anthropic.com"), disposition: "prompt")
        let outcome = AllowlistEvaluator.evaluate(
            flow: originFlow(ruid: 0, unattributed: true),
            rules: [r],
            agentOrigin: uidOrigin()
        )
        XCTAssertEqual(outcome, .uncertain)
    }

    func testHigh1_natMode_unattributedKeepsExistingSemantics() {
        // KEYED ON UID MODE: NAT mode, where `.unattributed` flows are
        // common (unsigned processes), keeps its existing rule-loop
        // semantics unchanged.
        let r = rule(host: .single("api.anthropic.com"), disposition: "allow")
        let outcome = AllowlistEvaluator.evaluate(
            flow: originFlow(ruid: 0, unattributed: true),
            rules: [r],
            agentOrigin: natOrigin()
        )
        XCTAssertEqual(outcome, .allow(matchedRuleId: "r-1"))
    }

    func testHigh1_noDescriptor_unattributedKeepsExistingSemantics() {
        // No descriptor delivered: not uid mode, so the hardening does not
        // key in (there are no uid-mode agent grants to inherit in that
        // state; the machine-wide default-deny posture is unchanged).
        let r = rule(host: .single("api.anthropic.com"), disposition: "allow")
        let outcome = AllowlistEvaluator.evaluate(
            flow: originFlow(ruid: 0, unattributed: true),
            rules: [r],
            agentOrigin: nil
        )
        XCTAssertEqual(outcome, .allow(matchedRuleId: "r-1"))
    }

    // NAT mode

    func testNatMode_egressHelperIsAgentDenyUnlessAllowlisted() {
        let outcome = AllowlistEvaluator.evaluate(
            flow: originFlow(signingId: "ai.sanctuaryprotocol.egress-helper"),
            rules: [],
            agentOrigin: natOrigin()
        )
        XCTAssertEqual(outcome, .drop(matchedRuleId: nil))
    }

    func testNatMode_nonMatchingSigningIdFastPathAllows() {
        let outcome = AllowlistEvaluator.evaluate(
            flow: originFlow(signingId: "com.apple.Safari"),
            rules: [],
            agentOrigin: natOrigin()
        )
        XCTAssertEqual(outcome, .allow(matchedRuleId: AllowlistEvaluator.operatorBaselineUidRuleId))
    }

    func testNatMode_unresolvedSigningIdDropsFailClosed() {
        // Decoded but no signing identity => unattributed => deny side.
        let outcome = AllowlistEvaluator.evaluate(
            flow: originFlow(signingId: nil, teamId: nil),
            rules: [],
            agentOrigin: natOrigin()
        )
        XCTAssertEqual(outcome, .drop(matchedRuleId: nil))
    }

    // No agentOrigin: everything is agent (machine-wide default-deny)

    func testNoAgentOrigin_everythingClassifiesAgentDefaultDeny() {
        // Even a low operator-looking uid: with no descriptor, treat as agent.
        let outcome = AllowlistEvaluator.evaluate(
            flow: originFlow(ruid: 1),
            rules: [],
            agentOrigin: nil
        )
        XCTAssertEqual(outcome, .drop(matchedRuleId: nil))
    }

    func testNoAgentOrigin_allowlistStillApplies() {
        let r = rule(host: .single("api.anthropic.com"), disposition: "allow")
        let outcome = AllowlistEvaluator.evaluate(
            flow: originFlow(ruid: 1),
            rules: [r],
            agentOrigin: nil
        )
        XCTAssertEqual(outcome, .allow(matchedRuleId: "r-1"))
    }

    /// The legacy "unknown" templateId must never be confused with the
    /// operator passthrough allow: an unattributed flow whose agent/template
    /// resolved to "unknown" still drops on an empty ruleset.
    func testUnknownTemplateNeverReachesOperatorAllow() {
        let outcome = AllowlistEvaluator.evaluate(
            flow: originFlow(ruid: 0, host: nil, unattributed: true),
            rules: [],
            agentOrigin: natOrigin()
        )
        XCTAssertEqual(outcome, .drop(matchedRuleId: nil))
    }
}
