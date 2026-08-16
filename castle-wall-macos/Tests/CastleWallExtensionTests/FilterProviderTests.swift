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
        port: Int = 443,
        sourceRuid: uid_t = 0
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
            opaqueDestination: host == nil,
            sourceRuid: sourceRuid,
            // Attributed agent flow: these fixtures exercise the allowlist
            // allow-path, not the #905 unattributed fail-closed suppression.
            sourceUnattributed: false
        )
    }

    // AR-1: a uid-mode origin descriptor. agentUid 600 is the confined agent;
    // any ruid >= systemUidAllowCeiling (500) that is not 600 classifies as the
    // OPERATOR (the recovery carve-out target). ruid 600 classifies as the AGENT.
    func uidOrigin() -> AgentOriginDescriptor {
        return AgentOriginDescriptor(mode: .uid, agentUid: 600, systemUidAllowCeiling: 500)
    }

    func loadStore(_ store: ManifestStore, rules: [ManifestRule]) {
        let snapshot = ManifestSnapshot(
            signatureB64url: "sig",
            rules: rules,
            updatedAt: Date()
        )
        store.update(snapshot)
    }

    func arm(_ engine: FlowEvaluatorEngine) {
        engine.armLease.update(ArmLeaseUpdate(
            armed: true,
            ttlSeconds: nil,
            heartbeatIntervalSeconds: 5
        ))
    }

    // MARK: - evaluate(_:) verdict path

    func testEvaluateReturnsAllowForMatchingRule() {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let engine = FlowEvaluatorEngine(manifestStore: store, flowCache: cache)
        arm(engine)
        loadStore(store, rules: [rule(id: "r-allow", host: "api.anthropic.com", disposition: "allow")])

        let outcome = engine.evaluate(flow())
        XCTAssertEqual(outcome, .allow(matchedRuleId: "r-allow"))
    }

    func testEvaluateReturnsDropForDenyMatch() {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let engine = FlowEvaluatorEngine(manifestStore: store, flowCache: cache)
        arm(engine)
        loadStore(store, rules: [rule(id: "r-deny", host: "api.anthropic.com", disposition: "deny")])

        let outcome = engine.evaluate(flow())
        XCTAssertEqual(outcome, .drop(matchedRuleId: "r-deny"))
    }

    func testEvaluateDefaultDeniesWhenNoMatch() {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let engine = FlowEvaluatorEngine(manifestStore: store, flowCache: cache)
        arm(engine)
        loadStore(store, rules: [rule(host: "other.example.com")])

        let outcome = engine.evaluate(flow(host: "novel.example.com"))
        XCTAssertEqual(outcome, .drop(matchedRuleId: nil))
    }

    // AR-1: an expired dead-man lease fails CLOSED for an AGENT (the default,
    // no agentOrigin => everything classifies .agent). A flow the manifest WOULD
    // have allowed is denied with the dead-man audit id; the fail-open no longer
    // hands an agent an unconfined window.
    func testExpiredArmLeaseFailsClosedForAgent() {
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
        // The manifest WOULD allow this host; the dead-man window overrides.
        loadStore(store, rules: [rule(host: "api.anthropic.com", disposition: "allow")])

        let outcome = engine.evaluate(flow(host: "api.anthropic.com"))
        XCTAssertEqual(outcome, .drop(matchedRuleId: ArmLease.failClosedDeadManRuleId))
        XCTAssertEqual(cache.count, 0, "degraded verdicts must not outlive a renewed lease")
    }

    // AR-1 carve-out: the SAME expired dead-man lease still fails OPEN for the
    // OPERATOR, so an SSH-only operator can recover a daemon-down box. Same lease
    // state, operator ruid (601 >= ceiling 500, != agentUid 600).
    func testExpiredArmLeaseFailsOpenForOperatorRecovery() {
        var now = Date(timeIntervalSince1970: 100)
        let lease = ArmLease(now: { now })
        lease.update(ArmLeaseUpdate(armed: true, ttlSeconds: 10, heartbeatIntervalSeconds: 5))
        now = Date(timeIntervalSince1970: 111)

        let store = ManifestStore()
        let engine = FlowEvaluatorEngine(
            manifestStore: store,
            agentOrigin: uidOrigin(),
            armLease: lease
        )
        loadStore(store, rules: [rule(host: "api.anthropic.com", disposition: "allow")])

        XCTAssertEqual(
            engine.evaluate(flow(host: "blocked.example.com", sourceRuid: 601)),
            .allow(matchedRuleId: ArmLease.failOpenRuleId)
        )
    }

    // AR-1: the agent side under an EXPLICIT uid origin (ruid 600 == agentUid)
    // still fails closed on the same lease.
    func testExpiredArmLeaseFailsClosedForConfinedAgentUid() {
        var now = Date(timeIntervalSince1970: 100)
        let lease = ArmLease(now: { now })
        lease.update(ArmLeaseUpdate(armed: true, ttlSeconds: 10, heartbeatIntervalSeconds: 5))
        now = Date(timeIntervalSince1970: 111)

        let store = ManifestStore()
        let engine = FlowEvaluatorEngine(
            manifestStore: store,
            agentOrigin: uidOrigin(),
            armLease: lease
        )
        loadStore(store, rules: [rule(host: "api.anthropic.com", disposition: "allow")])

        XCTAssertEqual(
            engine.evaluate(flow(host: "api.anthropic.com", sourceRuid: 600)),
            .drop(matchedRuleId: ArmLease.failClosedDeadManRuleId)
        )
    }

    func testStoppedHeartbeatFailsClosedForAgentNoManifest() {
        var now = Date(timeIntervalSince1970: 200)
        let lease = ArmLease(now: { now })
        lease.update(ArmLeaseUpdate(armed: true, ttlSeconds: nil, heartbeatIntervalSeconds: 5))
        now = Date(timeIntervalSince1970: 211)

        // No manifest to consult: an agent flow still fails CLOSED during the
        // dead-man window (never passes on a degraded, unverifiable posture).
        let engine = FlowEvaluatorEngine(armLease: lease)
        XCTAssertEqual(
            engine.evaluate(flow(host: "blocked.example.com")),
            .drop(matchedRuleId: ArmLease.failClosedDeadManRuleId)
        )
    }

    func testRevokedArmLeaseFailsClosedForAgent() {
        let lease = ArmLease()
        lease.update(ArmLeaseUpdate(armed: false, revoked: true, ttlSeconds: nil, heartbeatIntervalSeconds: 5))

        XCTAssertEqual(lease.failOpenReason(), "lease_revoked")

        let engine = FlowEvaluatorEngine(armLease: lease)
        XCTAssertEqual(
            engine.evaluate(flow(host: "blocked.example.com")),
            .drop(matchedRuleId: ArmLease.failClosedDeadManRuleId)
        )
    }

    func testMissingArmLeaseForcesAllowRuleClosed() {
        let store = ManifestStore()
        let engine = FlowEvaluatorEngine(manifestStore: store, armLease: ArmLease())
        loadStore(store, rules: [rule(host: "api.anthropic.com", disposition: "allow")])

        XCTAssertEqual(engine.armLease.missingLeaseReason(), "arm_lease_missing")
        XCTAssertEqual(
            engine.evaluate(flow(host: "api.anthropic.com")),
            .drop(matchedRuleId: ArmLease.missingLeaseRuleId)
        )
    }

    func testMissingManifestAndMissingArmLeaseDropsClosed() {
        let store = ManifestStore()
        let engine = FlowEvaluatorEngine(manifestStore: store, armLease: ArmLease())

        XCTAssertNil(store.currentSnapshot())
        XCTAssertEqual(engine.armLease.missingLeaseReason(), "arm_lease_missing")
        XCTAssertEqual(
            engine.evaluate(flow(host: "api.anthropic.com")),
            .drop(matchedRuleId: nil)
        )
    }

    func testDaemonDetachedLeaseStillEnforcesManifest() {
        let lease = ArmLease()
        lease.update(ArmLeaseUpdate(armed: true, ttlSeconds: nil, heartbeatIntervalSeconds: 5))
        lease.update(ArmLeaseUpdate(armed: false, ttlSeconds: nil, heartbeatIntervalSeconds: 5))

        let store = ManifestStore()
        let engine = FlowEvaluatorEngine(manifestStore: store, armLease: lease)
        loadStore(store, rules: [rule(host: "blocked.example.com", disposition: "deny")])

        XCTAssertNil(lease.failOpenReason())
        XCTAssertEqual(
            engine.evaluate(flow(host: "blocked.example.com")),
            .drop(matchedRuleId: "r-1")
        )
    }

    func testRevokeSurvivesGracefulDaemonDetach() {
        // Lockout regression guard: after an operator revoke, a graceful
        // daemon-detach (armed=false WITHOUT the revoke flag) must not clear
        // the revoked state — else the wall silently re-enforces with no
        // heartbeat tripwire left. Only an explicit re-arm clears revoke.
        let lease = ArmLease()
        lease.update(ArmLeaseUpdate(armed: false, revoked: true, ttlSeconds: nil, heartbeatIntervalSeconds: 5))
        XCTAssertEqual(lease.failOpenReason(), "lease_revoked")

        lease.update(ArmLeaseUpdate(armed: false, ttlSeconds: nil, heartbeatIntervalSeconds: 5))

        XCTAssertEqual(lease.failOpenReason(), "lease_revoked")
        XCTAssertTrue(lease.snapshot().revoked)
    }

    func testArmLeaseRearmAfterRevokeRestoresEnforcement() {
        let lease = ArmLease()
        lease.update(ArmLeaseUpdate(armed: false, revoked: true, ttlSeconds: nil, heartbeatIntervalSeconds: 5))
        XCTAssertEqual(lease.failOpenReason(), "lease_revoked")

        lease.update(ArmLeaseUpdate(armed: true, ttlSeconds: nil, heartbeatIntervalSeconds: 5))

        XCTAssertNil(lease.failOpenReason())
        XCTAssertFalse(lease.snapshot().revoked)
        let store = ManifestStore()
        let engine = FlowEvaluatorEngine(manifestStore: store, armLease: lease)
        loadStore(store, rules: [rule(host: "blocked.example.com", disposition: "deny")])
        XCTAssertEqual(
            engine.evaluate(flow(host: "blocked.example.com")),
            .drop(matchedRuleId: "r-1")
        )
    }

    func testEvaluateReturnsUncertainWhenOnlyPromptMatches() {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let engine = FlowEvaluatorEngine(manifestStore: store, flowCache: cache)
        arm(engine)
        loadStore(store, rules: [rule(host: "api.anthropic.com", disposition: "prompt")])

        let outcome = engine.evaluate(flow())
        XCTAssertEqual(outcome, .uncertain)
    }

    // MARK: - Cache wiring

    func testEvaluateCachesAllowOutcome() {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let engine = FlowEvaluatorEngine(manifestStore: store, flowCache: cache)
        arm(engine)
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
        arm(engine)
        loadStore(store, rules: [rule(host: "api.anthropic.com", disposition: "deny")])

        _ = engine.evaluate(flow())
        XCTAssertEqual(cache.count, 1)
    }

    func testEvaluateDoesNotCacheUncertain() {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let engine = FlowEvaluatorEngine(manifestStore: store, flowCache: cache)
        arm(engine)
        loadStore(store, rules: [rule(host: "api.anthropic.com", disposition: "prompt")])

        _ = engine.evaluate(flow())
        XCTAssertEqual(cache.count, 0)
    }

    func testManifestUpdateClearsCache() {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let engine = FlowEvaluatorEngine(manifestStore: store, flowCache: cache)
        arm(engine)
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
