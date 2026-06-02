//
// OriginClassifierTests.swift
//
// Fail-closed origin-classification tests (2026-05-29 origin-classifier
// foundation). These tests exist to PROVE the hard security invariant:
//
//   ONLY a positive `.operator` determination earns the allow fast-path.
//   `.agent` AND `.unattributed` BOTH route to the default-deny + allowlist
//   path. A nil / undecodable / unattributed token is `.unattributed`
//   (=> deny side). When no agentOrigin descriptor has been delivered,
//   everything classifies `.agent`. There is NO path where "could not
//   determine origin" reaches operator-allow.
//

import XCTest
@testable import CastleWallFilter
import CastleWallIPC

final class OriginClassifierTests: XCTestCase {

    // MARK: - Descriptor builders

    /// A descriptor that POSITIVELY decoded (sourceUnattributed == false).
    private func attributed(
        ruid: uid_t = 501,
        pid: pid_t = 4242,
        pidVersion: Int32 = 1,
        signingId: String? = nil,
        teamId: String? = nil,
        port: Int = 443
    ) -> FilterFlowDescriptor {
        return FilterFlowDescriptor(
            sourceAppIdentifier: "deadbeef",
            agentId: "deadbeef",
            templateId: "unknown",
            destinationHost: "api.anthropic.com",
            destinationIp: "104.18.32.10",
            destinationPort: port,
            networkProtocol: .tcp,
            hostnameSource: "sni",
            opaqueDestination: false,
            sourceRuid: ruid,
            sourcePid: pid,
            sourcePidVersion: pidVersion,
            sourceSigningId: signingId,
            sourceTeamId: teamId,
            sourceUnattributed: false
        )
    }

    /// A descriptor the provider could NOT positively attribute.
    private func unattributedFlow() -> FilterFlowDescriptor {
        return FilterFlowDescriptor(
            sourceAppIdentifier: "unknown",
            agentId: "unknown",
            templateId: "unknown",
            destinationHost: "api.anthropic.com",
            destinationIp: "104.18.32.10",
            destinationPort: 443,
            networkProtocol: .tcp,
            hostnameSource: "sni",
            opaqueDestination: false,
            sourceUnattributed: true
        )
    }

    private func uidOrigin(
        agentUid: uid_t? = 600,
        ceiling: uid_t = 500
    ) -> AgentOriginDescriptor {
        return AgentOriginDescriptor(
            mode: .uid,
            agentUid: agentUid,
            systemUidAllowCeiling: ceiling
        )
    }

    private func natOrigin(
        signingId: String? = "ai.sanctuaryprotocol.egress-helper",
        teamId: String? = nil,
        portRange: ClosedRange<Int>? = nil
    ) -> AgentOriginDescriptor {
        return AgentOriginDescriptor(
            mode: .nat,
            egressHelperSigningId: signingId,
            egressHelperTeamId: teamId,
            agentRuntimePortRange: portRange,
            systemUidAllowCeiling: 500
        )
    }

    // MARK: - Invariant 1: unattributed ALWAYS fails closed, every mode

    func testUnattributedIsAlwaysUnattributed_uidMode() {
        let oc = OriginClassifier.originClass(
            descriptor: unattributedFlow(),
            agentOrigin: uidOrigin()
        )
        XCTAssertEqual(oc, .unattributed)
    }

    func testUnattributedIsAlwaysUnattributed_natMode() {
        let oc = OriginClassifier.originClass(
            descriptor: unattributedFlow(),
            agentOrigin: natOrigin()
        )
        XCTAssertEqual(oc, .unattributed)
    }

    func testUnattributedIsAgentSide_noOrigin() {
        // No descriptor + unattributed: unattributed dominates -> deny side.
        let oc = OriginClassifier.originClass(
            descriptor: unattributedFlow(),
            agentOrigin: nil
        )
        XCTAssertEqual(oc, .unattributed)
    }

    /// An unattributed flow even with a system-low ruid value present in the
    /// struct must NOT reach operator: sourceUnattributed dominates.
    func testUnattributedWithLowUidValueStillUnattributed() {
        var flow = unattributedFlow()
        flow = FilterFlowDescriptor(
            sourceAppIdentifier: flow.sourceAppIdentifier,
            agentId: flow.agentId,
            templateId: flow.templateId,
            destinationHost: flow.destinationHost,
            destinationIp: flow.destinationIp,
            destinationPort: flow.destinationPort,
            networkProtocol: flow.networkProtocol,
            hostnameSource: flow.hostnameSource,
            opaqueDestination: flow.opaqueDestination,
            sourceRuid: 0, // root-ish value that WOULD be operator if decoded
            sourcePid: 1,
            sourcePidVersion: 0,
            sourceSigningId: nil,
            sourceTeamId: nil,
            sourceUnattributed: true // ... but it was NOT decoded.
        )
        XCTAssertEqual(
            OriginClassifier.originClass(descriptor: flow, agentOrigin: uidOrigin()),
            .unattributed
        )
    }

    // MARK: - Invariant 2: no agentOrigin => everything .agent (never operator)

    func testNoOriginClassifiesAttributedAsAgent() {
        let oc = OriginClassifier.originClass(
            descriptor: attributed(ruid: 0), // even root
            agentOrigin: nil
        )
        XCTAssertEqual(oc, .agent)
    }

    // MARK: - UID mode

    func testUidMode_agentUidFlowIsAgent() {
        let oc = OriginClassifier.originClass(
            descriptor: attributed(ruid: 600),
            agentOrigin: uidOrigin(agentUid: 600, ceiling: 500)
        )
        XCTAssertEqual(oc, .agent)
    }

    func testUidMode_systemLowUidIsOperator() {
        // ruid below the ceiling = system daemon = conceded operator path.
        let oc = OriginClassifier.originClass(
            descriptor: attributed(ruid: 1),
            agentOrigin: uidOrigin(agentUid: 600, ceiling: 500)
        )
        XCTAssertEqual(oc, .operator)
    }

    func testUidMode_operatorHighUidIsOperator() {
        let oc = OriginClassifier.originClass(
            descriptor: attributed(ruid: 501),
            agentOrigin: uidOrigin(agentUid: 600, ceiling: 500)
        )
        XCTAssertEqual(oc, .operator)
    }

    // MARK: - NAT mode

    func testNatMode_egressHelperSigningIdIsAgent() {
        let oc = OriginClassifier.originClass(
            descriptor: attributed(signingId: "ai.sanctuaryprotocol.egress-helper"),
            agentOrigin: natOrigin(signingId: "ai.sanctuaryprotocol.egress-helper")
        )
        XCTAssertEqual(oc, .agent)
    }

    func testNatMode_nonMatchingSigningIdIsOperator() {
        let oc = OriginClassifier.originClass(
            descriptor: attributed(signingId: "com.apple.Safari"),
            agentOrigin: natOrigin(signingId: "ai.sanctuaryprotocol.egress-helper")
        )
        XCTAssertEqual(oc, .operator)
    }

    func testNatMode_noSigningIdentityIsUnattributed() {
        // Decoded uid/pid but NO signing identity: NAT mode cannot place it
        // -> fail closed to unattributed (deny side), NOT operator.
        let oc = OriginClassifier.originClass(
            descriptor: attributed(signingId: nil, teamId: nil),
            agentOrigin: natOrigin(signingId: "ai.sanctuaryprotocol.egress-helper")
        )
        XCTAssertEqual(oc, .unattributed)
    }

    func testNatMode_teamIdMustAlsoMatchWhenConfigured() {
        // SigningID matches but configured TeamID does not -> not the helper
        // -> operator (resolved identity that is not the agent).
        let oc = OriginClassifier.originClass(
            descriptor: attributed(signingId: "ai.sanctuaryprotocol.egress-helper", teamId: "WRONGTEAM"),
            agentOrigin: natOrigin(signingId: "ai.sanctuaryprotocol.egress-helper", teamId: "YFQSWQ9BJN")
        )
        XCTAssertEqual(oc, .operator)
    }

    func testNatMode_signingMatchOutsidePortRangeStaysAgentNotOperator() {
        // Even when the flow's port is outside the configured runtime range,
        // a signing-id match must NEVER relax to operator. Worst case: agent.
        let oc = OriginClassifier.originClass(
            descriptor: attributed(signingId: "ai.sanctuaryprotocol.egress-helper", port: 9999),
            agentOrigin: natOrigin(
                signingId: "ai.sanctuaryprotocol.egress-helper",
                portRange: 49152...65535
            )
        )
        XCTAssertEqual(oc, .agent)
    }

    // MARK: - Wire -> descriptor conversion fail-closed

    func testWireUidMissingAgentUidIsRejected() {
        let wire = AgentOriginWire(mode: .uid, agentUid: nil, systemUidAllowCeiling: 500)
        XCTAssertNil(AgentOriginDescriptor(wire: wire))
    }

    func testWireNatMissingBothIdentitiesIsRejected() {
        let wire = AgentOriginWire(
            mode: .nat,
            egressHelperSigningId: nil,
            egressHelperTeamId: nil,
            systemUidAllowCeiling: 500
        )
        XCTAssertNil(AgentOriginDescriptor(wire: wire))
    }

    func testWireUidValidConverts() {
        let wire = AgentOriginWire(mode: .uid, agentUid: 600, systemUidAllowCeiling: 500)
        let d = AgentOriginDescriptor(wire: wire)
        XCTAssertEqual(d?.mode, .uid)
        XCTAssertEqual(d?.agentUid, 600)
        XCTAssertEqual(d?.systemUidAllowCeiling, 500)
    }

    func testWireNatPortRangeConverts() {
        let wire = AgentOriginWire(
            mode: .nat,
            egressHelperSigningId: "id",
            agentRuntimePortRange: [49152, 65535],
            systemUidAllowCeiling: 500
        )
        let d = AgentOriginDescriptor(wire: wire)
        XCTAssertEqual(d?.agentRuntimePortRange, 49152...65535)
    }

    func testWireNatMalformedPortRangeDropsRangeNotDescriptor() {
        // A 1-element range is malformed; the descriptor still converts (it
        // has a signing id) but the range is dropped rather than guessed.
        let wire = AgentOriginWire(
            mode: .nat,
            egressHelperSigningId: "id",
            agentRuntimePortRange: [49152],
            systemUidAllowCeiling: 500
        )
        let d = AgentOriginDescriptor(wire: wire)
        XCTAssertNotNil(d)
        XCTAssertNil(d?.agentRuntimePortRange)
    }
}
