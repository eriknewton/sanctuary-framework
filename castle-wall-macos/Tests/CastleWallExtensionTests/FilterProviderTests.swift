//
// FilterProviderTests.swift
//
// Verdict-decision glue exercised through `FlowEvaluatorEngine`. The
// engine holds the same `ManifestStore` + `FlowCache` substrate the
// provider does and exposes the testable `evaluate(_:)` entry point.
//
// `CastleWallFilterProvider` itself is NOT instantiated in these tests:
// `NEFilterDataProvider`'s initializer asserts a sysextd-loaded context
// that does not exist in a plain XCTest process and crashes the test
// runner if invoked outside that context. Loaded-extension integration
// tests in Alpha-3 cover the framework adapter end-to-end.
//
// `verdict(for:)` translation is exercised here against synthesized
// `EvaluationOutcome` values; that surface is a pure-Swift static
// function and works without instantiating the provider class.
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
        let engine = FlowEvaluatorEngine(manifestStore: store, flowCache: cache)
        loadStore(store, rules: [rule(id: "r-allow", host: "api.anthropic.com", disposition: "allow")])

        let outcome = engine.evaluate(flow())
        XCTAssertEqual(outcome, .allow(matchedRuleId: "r-allow"))
    }

    func testEvaluateReturnsDropForDenyMatch() {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let engine = FlowEvaluatorEngine(manifestStore: store, flowCache: cache)
        loadStore(store, rules: [rule(id: "r-deny", host: "api.anthropic.com", disposition: "deny")])

        let outcome = engine.evaluate(flow())
        XCTAssertEqual(outcome, .drop(matchedRuleId: "r-deny"))
    }

    func testEvaluateDefaultDeniesWhenNoMatch() {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let engine = FlowEvaluatorEngine(manifestStore: store, flowCache: cache)
        loadStore(store, rules: [rule(host: "other.example.com")])

        let outcome = engine.evaluate(flow(host: "novel.example.com"))
        XCTAssertEqual(outcome, .drop(matchedRuleId: nil))
    }

    func testExpiredArmLeaseFailsOpenWithAuditMarker() {
        var now = Date(timeIntervalSince1970: 100)
        let lease = ArmLease(now: { now })
        lease.update(ArmLeaseUpdate(armed: true, ttlSeconds: 10, heartbeatIntervalSeconds: 5))
        now = Date(timeIntervalSince1970: 111)

        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let engine = FlowEvaluatorEngine(
            manifestStore: store,
            flowCache: cache,
            armLease: lease
        )
        loadStore(store, rules: [rule(host: "other.example.com")])

        let outcome = engine.evaluate(flow(host: "novel.example.com"))
        XCTAssertEqual(outcome, .allow(matchedRuleId: ArmLease.failOpenRuleId))
        XCTAssertEqual(cache.count, 0, "fail-open verdicts must not outlive a renewed lease")
    }

    func testStoppedHeartbeatFailsOpenWithAuditMarker() {
        var now = Date(timeIntervalSince1970: 200)
        let lease = ArmLease(now: { now })
        lease.update(ArmLeaseUpdate(armed: true, ttlSeconds: nil, heartbeatIntervalSeconds: 5))
        now = Date(timeIntervalSince1970: 211)

        let engine = FlowEvaluatorEngine(armLease: lease)
        XCTAssertEqual(
            engine.evaluate(flow(host: "blocked.example.com")),
            .allow(matchedRuleId: ArmLease.failOpenRuleId)
        )
    }

    func testEvaluateReturnsUncertainWhenOnlyPromptMatches() {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let engine = FlowEvaluatorEngine(manifestStore: store, flowCache: cache)
        loadStore(store, rules: [rule(host: "api.anthropic.com", disposition: "prompt")])

        let outcome = engine.evaluate(flow())
        XCTAssertEqual(outcome, .uncertain)
    }

    // MARK: - Cache wiring

    func testEvaluateCachesAllowOutcome() {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let engine = FlowEvaluatorEngine(manifestStore: store, flowCache: cache)
        loadStore(store, rules: [rule(host: "api.anthropic.com", disposition: "allow")])

        _ = engine.evaluate(flow())
        XCTAssertEqual(cache.count, 1)

        // Second evaluation returns the cached value even if the manifest
        // is replaced under us with an empty rule set, until the manifest
        // change observer fires the cache clear.
        let outcome = engine.evaluate(flow())
        XCTAssertEqual(outcome, .allow(matchedRuleId: "r-1"))
    }

    func testEvaluateCachesDropOutcome() {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let engine = FlowEvaluatorEngine(manifestStore: store, flowCache: cache)
        loadStore(store, rules: [rule(host: "api.anthropic.com", disposition: "deny")])

        _ = engine.evaluate(flow())
        XCTAssertEqual(cache.count, 1)
    }

    func testEvaluateDoesNotCacheUncertain() {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let engine = FlowEvaluatorEngine(manifestStore: store, flowCache: cache)
        loadStore(store, rules: [rule(host: "api.anthropic.com", disposition: "prompt")])

        _ = engine.evaluate(flow())
        XCTAssertEqual(cache.count, 0)
    }

    func testManifestUpdateClearsCache() {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let engine = FlowEvaluatorEngine(manifestStore: store, flowCache: cache)
        loadStore(store, rules: [rule(id: "r-allow", disposition: "allow")])
        _ = engine.evaluate(flow())
        XCTAssertEqual(cache.count, 1)

        // Replace the snapshot. The engine's manifest-store observer
        // should have cleared the cache.
        loadStore(store, rules: [rule(id: "r-deny", disposition: "deny")])
        XCTAssertEqual(cache.count, 0)

        let outcome = engine.evaluate(flow())
        XCTAssertEqual(outcome, .drop(matchedRuleId: "r-deny"))
    }

    // MARK: - Verdict translation
    //
    // `verdict(for:)` is a pure-Swift static method on the provider class.
    // Calling it does NOT instantiate `NEFilterDataProvider` (no sysextd
    // context required); only the framework verdict factory methods are
    // touched, which work in any process.

    func testVerdictTranslationMapsOutcomesToFrameworkVerdicts() {
        let allow = CastleWallFilterProvider.verdict(for: .allow(matchedRuleId: "r-1"))
        let drop = CastleWallFilterProvider.verdict(for: .drop(matchedRuleId: nil))
        let pending = CastleWallFilterProvider.verdict(for: .uncertain)

        XCTAssertNotNil(allow)
        XCTAssertNotNil(drop)
        XCTAssertNotNil(pending)
        // Allow vs drop verdicts must not be the same object reference.
        XCTAssertFalse(allow === drop)
    }

    func testUnsupportedFlowVerdictFailsClosedWithDiagnostic() {
        var diagnostics: [String] = []

        let verdict = CastleWallFilterProvider.verdictForUnsupportedFlow(
            flowType: "NEFilterBrowserFlow"
        ) { message in
            diagnostics.append(message)
        }

        XCTAssertNotNil(verdict)
        XCTAssertEqual(diagnostics, ["unsupported flow shape denied: NEFilterBrowserFlow"])
        XCTAssertFalse(verdict === CastleWallFilterProvider.verdict(for: .allow(matchedRuleId: "r-allow")))
    }
}
