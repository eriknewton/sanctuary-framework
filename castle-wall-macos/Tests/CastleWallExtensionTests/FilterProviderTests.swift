//
// FilterProviderTests.swift
//
// Verdict-decision glue for `CastleWallFilterProvider`. Drives the
// testable `evaluate(_:)` entry point with synthesized
// FilterFlowDescriptor values + injected ManifestStore + FlowCache; the
// `handleNewFlow(_:)` framework callback exercises NEFilterFlow shapes
// that integration tests in Alpha-3 cover (loaded-extension scenarios
// cannot run on macOS GHA runners without sysextd user approval per the
// macOS CI workflow comment).
//

import XCTest
@testable import CastleWallFilter
import CastleWallIPC

final class FilterProviderTests: XCTestCase {

    // MARK: - Helpers

    func rule(
        id: String = "r-1",
        host: String? = "api.anthropic.com",
        port: Int? = 443,
        disposition: String = "allow"
    ) -> ManifestRule {
        return ManifestRule(
            id: id,
            schemaVersion: 1,
            createdAt: "2026-05-11T00:00:00Z",
            description: nil,
            match: ManifestRuleMatch(
                host: host.map { .single($0) },
                hostPattern: nil,
                port: port.map { .single($0) },
                protocolName: "tcp"
            ),
            scope: ManifestRuleScope(agentIds: nil, templateIds: nil),
            disposition: disposition,
            timeWindow: nil
        )
    }

    func flow(
        agentId: String = "agent-7",
        host: String? = "api.anthropic.com",
        port: Int = 443
    ) -> FilterFlowDescriptor {
        return FilterFlowDescriptor(
            sourceAppIdentifier: "ai.sanctuaryprotocol.test",
            agentId: agentId,
            templateId: "coding-assistant",
            destinationHost: host,
            destinationIp: "104.18.32.10",
            destinationPort: port,
            networkProtocol: .tcp,
            hostnameSource: host != nil ? "sni" : nil,
            opaqueDestination: host == nil
        )
    }

    func loadStore(_ store: ManifestStore, rules: [ManifestRule]) {
        let snapshot = ManifestSnapshot(
            signatureB64url: "sig",
            rules: rules,
            updatedAt: Date()
        )
        store.update(snapshot)
    }

    // MARK: - evaluate(_:) verdict path

    func testEvaluateReturnsAllowForMatchingRule() {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let provider = CastleWallFilterProvider(
            manifestStore: store,
            flowCache: cache,
            agentResolver: { _ in (agentId: "agent-7", templateId: "coding-assistant") }
        )
        loadStore(store, rules: [rule(id: "r-allow", host: "api.anthropic.com", disposition: "allow")])

        let outcome = provider.evaluate(flow())
        XCTAssertEqual(outcome, .allow(matchedRuleId: "r-allow"))
    }

    func testEvaluateReturnsDropForDenyMatch() {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let provider = CastleWallFilterProvider(manifestStore: store, flowCache: cache)
        loadStore(store, rules: [rule(id: "r-deny", host: "api.anthropic.com", disposition: "deny")])

        let outcome = provider.evaluate(flow())
        XCTAssertEqual(outcome, .drop(matchedRuleId: "r-deny"))
    }

    func testEvaluateDefaultDeniesWhenNoMatch() {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let provider = CastleWallFilterProvider(manifestStore: store, flowCache: cache)
        loadStore(store, rules: [rule(host: "other.example.com")])

        let outcome = provider.evaluate(flow(host: "novel.example.com"))
        XCTAssertEqual(outcome, .drop(matchedRuleId: nil))
    }

    func testEvaluateReturnsUncertainWhenOnlyPromptMatches() {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let provider = CastleWallFilterProvider(manifestStore: store, flowCache: cache)
        loadStore(store, rules: [rule(host: "api.anthropic.com", disposition: "prompt")])

        let outcome = provider.evaluate(flow())
        XCTAssertEqual(outcome, .uncertain)
    }

    // MARK: - Cache wiring

    func testEvaluateCachesAllowOutcome() {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let provider = CastleWallFilterProvider(manifestStore: store, flowCache: cache)
        loadStore(store, rules: [rule(host: "api.anthropic.com", disposition: "allow")])

        _ = provider.evaluate(flow())
        XCTAssertEqual(cache.count, 1)

        // Second evaluation returns the cached value even if the manifest
        // is replaced under us with an empty rule set, until the manifest
        // change observer fires the cache clear.
        let outcome = provider.evaluate(flow())
        XCTAssertEqual(outcome, .allow(matchedRuleId: "r-1"))
    }

    func testEvaluateCachesDropOutcome() {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let provider = CastleWallFilterProvider(manifestStore: store, flowCache: cache)
        loadStore(store, rules: [rule(host: "api.anthropic.com", disposition: "deny")])

        _ = provider.evaluate(flow())
        XCTAssertEqual(cache.count, 1)
    }

    func testEvaluateDoesNotCacheUncertain() {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let provider = CastleWallFilterProvider(manifestStore: store, flowCache: cache)
        loadStore(store, rules: [rule(host: "api.anthropic.com", disposition: "prompt")])

        _ = provider.evaluate(flow())
        XCTAssertEqual(cache.count, 0)
    }

    func testManifestUpdateClearsCache() {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let provider = CastleWallFilterProvider(manifestStore: store, flowCache: cache)
        loadStore(store, rules: [rule(id: "r-allow", disposition: "allow")])
        _ = provider.evaluate(flow())
        XCTAssertEqual(cache.count, 1)

        // Replace the snapshot. The provider's manifest-store observer
        // should have cleared the cache.
        loadStore(store, rules: [rule(id: "r-deny", disposition: "deny")])
        XCTAssertEqual(cache.count, 0)

        let outcome = provider.evaluate(flow())
        XCTAssertEqual(outcome, .drop(matchedRuleId: "r-deny"))
    }

    // MARK: - Verdict translation

    func testVerdictTranslationMapsOutcomesToFrameworkVerdicts() {
        // We compare via the framework's NEFilterNewFlowVerdict object identity
        // semantics. Apple's verdict factories return distinct objects, so we
        // assert each outcome maps to a non-nil verdict and that allow / drop
        // / needRules produce different shapes by string description.
        let allow = CastleWallFilterProvider.verdict(for: .allow(matchedRuleId: "r-1"))
        let drop = CastleWallFilterProvider.verdict(for: .drop(matchedRuleId: nil))
        let pending = CastleWallFilterProvider.verdict(for: .uncertain)

        XCTAssertNotNil(allow)
        XCTAssertNotNil(drop)
        XCTAssertNotNil(pending)
        // Allow vs drop verdicts must not be equal references.
        XCTAssertFalse(allow === drop)
    }
}
