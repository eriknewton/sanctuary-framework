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
}
