import XCTest
@testable import CastleWallFilter
@testable import CastleWallIPC

final class EnforcementAvailabilitySnapshotTests: XCTestCase {
    private final class TestClock {
        private var current: Date
        init(_ start: Date = Date(timeIntervalSince1970: 1_780_000_000)) {
            self.current = start
        }
        func now() -> Date { current }
        func advance(_ seconds: TimeInterval) { current = current.addingTimeInterval(seconds) }
    }

    private func makeEngine(clock: TestClock = TestClock()) -> FlowEvaluatorEngine {
        return FlowEvaluatorEngine(armLease: ArmLease(now: clock.now))
    }

    private func installManifest(_ engine: FlowEvaluatorEngine, signature: String? = "manifest-sig") {
        engine.manifestStore.update(
            ManifestSnapshot(
                signatureB64url: signature,
                rules: [],
                updatedAt: Date(timeIntervalSince1970: 1_780_000_000)
            )
        )
    }

    private func sampleFlow() -> FilterFlowDescriptor {
        return FilterFlowDescriptor(
            sourceAppIdentifier: "ai.sanctuaryprotocol.test",
            agentId: "agent-7",
            templateId: "coding-assistant",
            destinationHost: "api.anthropic.com",
            destinationIp: "104.18.32.10",
            destinationPort: 443,
            networkProtocol: .tcp,
            hostnameSource: "sni",
            opaqueDestination: false
        )
    }

    func testSnapshotStartsMissingAndManifestAbsent() {
        let engine = makeEngine()

        let snapshot = engine.enforcementAvailabilitySnapshot(providerBound: false)

        XCTAssertEqual(snapshot.source, "macos_extension")
        XCTAssertEqual(snapshot.protocolVersion, 1)
        XCTAssertEqual(snapshot.leaseState, "missing")
        XCTAssertEqual(snapshot.leaseReason, "arm_lease_missing")
        XCTAssertEqual(snapshot.manifestState, "absent")
        XCTAssertNil(snapshot.manifestSignatureB64url)
        XCTAssertFalse(snapshot.providerBound)
    }

    func testSnapshotDistinguishesUnarmedFromLive() {
        let engine = makeEngine()
        installManifest(engine)
        engine.armLease.update(
            ArmLeaseUpdate(
                armed: false,
                revoked: false,
                ttlSeconds: nil,
                heartbeatIntervalSeconds: 5
            )
        )

        let snapshot = engine.enforcementAvailabilitySnapshot(providerBound: true)

        XCTAssertEqual(snapshot.leaseState, "unarmed")
        XCTAssertEqual(snapshot.leaseReason, "not_armed")
        XCTAssertEqual(snapshot.manifestState, "applied")
        XCTAssertEqual(snapshot.manifestSignatureB64url, "manifest-sig")
        XCTAssertTrue(snapshot.providerBound)
    }

    func testSnapshotLiveRequiresArmedAppliedManifestAndProviderBound() {
        let engine = makeEngine()
        installManifest(engine)
        engine.armLease.update(
            ArmLeaseUpdate(
                armed: true,
                revoked: false,
                ttlSeconds: nil,
                heartbeatIntervalSeconds: 3600
            )
        )

        let live = engine.enforcementAvailabilitySnapshot(providerBound: true)
        XCTAssertEqual(live.leaseState, "live")
        XCTAssertEqual(live.leaseReason, "ok")
        XCTAssertEqual(live.manifestState, "applied")
        XCTAssertEqual(live.manifestSignatureB64url, "manifest-sig")
        XCTAssertTrue(live.providerBound)

        let providerStopped = engine.enforcementAvailabilitySnapshot(providerBound: false)
        XCTAssertEqual(providerStopped.leaseState, "live")
        XCTAssertEqual(providerStopped.leaseReason, "ok")
        XCTAssertFalse(providerStopped.providerBound)
    }

    func testSnapshotReportsFailOpenLeaseReasons() {
        let clock = TestClock()
        let engine = makeEngine(clock: clock)
        installManifest(engine)
        engine.armLease.update(
            ArmLeaseUpdate(
                armed: true,
                revoked: true,
                ttlSeconds: nil,
                heartbeatIntervalSeconds: 5
            )
        )

        let revoked = engine.enforcementAvailabilitySnapshot(providerBound: true)
        XCTAssertEqual(revoked.leaseState, "failed_open")
        XCTAssertEqual(revoked.leaseReason, "lease_revoked")

        engine.armLease.update(
            ArmLeaseUpdate(
                armed: true,
                revoked: false,
                ttlSeconds: 1,
                heartbeatIntervalSeconds: 3600
            )
        )
        clock.advance(2)

        let expired = engine.enforcementAvailabilitySnapshot(providerBound: true)
        XCTAssertEqual(expired.leaseState, "failed_open")
        XCTAssertEqual(expired.leaseReason, "ttl_expired")
    }

    func testFlowDecisionBuilderCarriesTheRealEmitterAvailabilityBlock() {
        let engine = makeEngine()
        installManifest(engine)
        engine.armLease.update(
            ArmLeaseUpdate(
                armed: true,
                revoked: false,
                ttlSeconds: nil,
                heartbeatIntervalSeconds: 3600
            )
        )
        let enforcement = engine.enforcementAvailabilitySnapshot(providerBound: true)

        let msg = IPCBridgeNotifications.buildFlowDecisionRecorded(
            outcome: .drop(matchedRuleId: "rule-deny"),
            flow: sampleFlow(),
            enforcement: enforcement
        )

        guard case .flowDecisionRecorded(let body) = msg else {
            return XCTFail("expected flow_decision_recorded")
        }
        XCTAssertEqual(body.enforcement, enforcement)
    }
}
