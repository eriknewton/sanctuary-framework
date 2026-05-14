//
// IPCBridgeNotificationsTests.swift
//
// Verify the four new IPC message variants: round-trip the JSON shape,
// confirm the bridge builders produce the expected envelope, and confirm
// `applyManifestUpdated` writes through to ManifestStore + clears
// FlowCache.
//

import XCTest
@testable import CastleWallFilter
@testable import CastleWallIPC

final class IPCBridgeNotificationsTests: XCTestCase {

    // MARK: - Round-trip of new IpcMessage variants

    func testManifestSubscribeRoundTrip() throws {
        let original = IpcMessage.manifestSubscribe(requestId: "abc123")
        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(IpcMessage.self, from: encoded)
        XCTAssertEqual(decoded, original)

        let json = String(data: encoded, encoding: .utf8) ?? ""
        XCTAssertTrue(json.contains("\"type\":\"manifest_subscribe\""))
        XCTAssertTrue(json.contains("\"request_id\":\"abc123\""))
    }

    func testManifestUpdatedRoundTrip() throws {
        let rule = ManifestRule(
            id: "rule-1",
            schemaVersion: 1,
            createdAt: "2026-05-11T00:00:00Z",
            description: "test",
            match: ManifestRuleMatch(
                host: .single("api.anthropic.com"),
                hostPattern: nil,
                port: .single(443),
                protocolName: "tcp"
            ),
            scope: ManifestRuleScope(agentIds: nil, templateIds: ["coding-assistant"]),
            disposition: "allow",
            timeWindow: nil
        )
        let signed = try makeSignedManifestUpdatedBody(rules: [rule])
        let body = signed.body
        let original = IpcMessage.manifestUpdated(body)
        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(IpcMessage.self, from: encoded)
        XCTAssertEqual(decoded, original)

        let json = String(data: encoded, encoding: .utf8) ?? ""
        XCTAssertTrue(json.contains("\"type\":\"manifest_updated\""))
        XCTAssertTrue(json.contains("\"signature_b64url\""))
        XCTAssertTrue(json.contains("\"rule-1\""))
    }

    func testFlowDecisionRecordedRoundTrip() throws {
        let body = FlowDecisionRecordedBody(
            decision: "allow",
            destination: IpcDestination(
                host: "api.anthropic.com",
                ip: "104.18.32.10",
                port: 443,
                protocolName: "tcp",
                hostnameSource: "sni",
                opaque: false
            ),
            agent: IpcAgentAttribution(id: "agent-7", template: "coding-assistant"),
            matchedRuleId: "rule-1",
            recordedAt: "2026-05-11T12:00:00Z"
        )
        let original = IpcMessage.flowDecisionRecorded(body)
        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(IpcMessage.self, from: encoded)
        XCTAssertEqual(decoded, original)

        let json = String(data: encoded, encoding: .utf8) ?? ""
        XCTAssertTrue(json.contains("\"type\":\"flow_decision_recorded\""))
        XCTAssertTrue(json.contains("\"matched_rule_id\":\"rule-1\""))
        XCTAssertTrue(json.contains("\"recorded_at\":\"2026-05-11T12:00:00Z\""))
    }

    func testFlowPendingApprovalRoundTrip() throws {
        let body = FlowPendingApprovalBody(
            requestId: "req-1",
            destination: IpcDestination(
                host: "novel.example.com",
                ip: "192.0.2.5",
                port: 443,
                protocolName: "tcp",
                hostnameSource: "sni",
                opaque: false
            ),
            agent: IpcAgentAttribution(id: "agent-3", template: "research-assistant"),
            surface: "egress",
            expiresInSeconds: 25
        )
        let original = IpcMessage.flowPendingApproval(body)
        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(IpcMessage.self, from: encoded)
        XCTAssertEqual(decoded, original)

        let json = String(data: encoded, encoding: .utf8) ?? ""
        XCTAssertTrue(json.contains("\"type\":\"flow_pending_approval\""))
        XCTAssertTrue(json.contains("\"surface\":\"egress\""))
        XCTAssertTrue(json.contains("\"expires_in_seconds\":25"))
    }

    // MARK: - IPCBridgeNotifications builders

    func testBuildSubscribeRequestUsesProvidedId() {
        let msg = IPCBridgeNotifications.buildSubscribeRequest(requestId: "fixed-id")
        XCTAssertEqual(msg, .manifestSubscribe(requestId: "fixed-id"))
    }

    func testBuildSubscribeRequestGeneratesIdWhenAbsent() {
        let msg = IPCBridgeNotifications.buildSubscribeRequest()
        guard case .manifestSubscribe(let requestId) = msg else {
            return XCTFail("expected manifest_subscribe")
        }
        // Hex-encoded 16 bytes is exactly 32 chars.
        XCTAssertEqual(requestId.count, 32)
    }

    func testBuildFlowDecisionRecordedAllow() {
        let flow = FilterFlowDescriptor(
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
        let outcome = EvaluationOutcome.allow(matchedRuleId: "rule-1")
        let msg = IPCBridgeNotifications.buildFlowDecisionRecorded(outcome: outcome, flow: flow)

        guard case .flowDecisionRecorded(let body) = msg else {
            return XCTFail("expected flow_decision_recorded")
        }
        XCTAssertEqual(body.decision, "allow")
        XCTAssertEqual(body.matchedRuleId, "rule-1")
        XCTAssertEqual(body.agent.id, "agent-7")
        XCTAssertEqual(body.destination.host, "api.anthropic.com")
        XCTAssertEqual(body.destination.port, 443)
        XCTAssertFalse(body.recordedAt.isEmpty)
    }

    func testBuildFlowDecisionRecordedDropWithNullRule() {
        let flow = FilterFlowDescriptor(
            sourceAppIdentifier: "ai.sanctuaryprotocol.test",
            agentId: "agent-9",
            templateId: "ops-runner",
            destinationHost: nil,
            destinationIp: "203.0.113.4",
            destinationPort: 8080,
            networkProtocol: .tcp,
            hostnameSource: nil,
            opaqueDestination: true
        )
        let outcome = EvaluationOutcome.drop(matchedRuleId: nil)
        let msg = IPCBridgeNotifications.buildFlowDecisionRecorded(outcome: outcome, flow: flow)

        guard case .flowDecisionRecorded(let body) = msg else {
            return XCTFail("expected flow_decision_recorded")
        }
        XCTAssertEqual(body.decision, "drop")
        XCTAssertNil(body.matchedRuleId)
        XCTAssertNil(body.destination.host)
        XCTAssertTrue(body.destination.opaque)
    }

    func testBuildFlowDecisionRecordedReturnsNilForUncertain() {
        let flow = FilterFlowDescriptor(
            sourceAppIdentifier: "ai.sanctuaryprotocol.test",
            agentId: "agent-9",
            templateId: "ops-runner",
            destinationHost: "novel.example.com",
            destinationIp: "192.0.2.5",
            destinationPort: 443,
            networkProtocol: .tcp,
            hostnameSource: "sni",
            opaqueDestination: false
        )
        let outcome = EvaluationOutcome.uncertain
        let msg = IPCBridgeNotifications.buildFlowDecisionRecorded(outcome: outcome, flow: flow)
        XCTAssertNil(msg)
    }

    func testBuildFlowPendingApproval() {
        let flow = FilterFlowDescriptor(
            sourceAppIdentifier: "ai.sanctuaryprotocol.test",
            agentId: "agent-3",
            templateId: "research-assistant",
            destinationHost: "novel.example.com",
            destinationIp: "192.0.2.5",
            destinationPort: 443,
            networkProtocol: .tcp,
            hostnameSource: "sni",
            opaqueDestination: false
        )
        let msg = IPCBridgeNotifications.buildFlowPendingApproval(
            flow: flow,
            requestId: "fixed-req-id",
            expiresInSeconds: 60
        )
        guard case .flowPendingApproval(let body) = msg else {
            return XCTFail("expected flow_pending_approval")
        }
        XCTAssertEqual(body.requestId, "fixed-req-id")
        XCTAssertEqual(body.surface, "egress")
        XCTAssertEqual(body.expiresInSeconds, 60)
        XCTAssertEqual(body.agent.id, "agent-3")
    }

    // MARK: - applyManifestUpdated wiring

    func testApplyManifestUpdatedWritesStoreAndClearsCache() throws {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        cache.put(
            FlowCacheKey(
                sourceAppIdentifier: "x",
                destinationHost: "h",
                destinationIp: "1.2.3.4",
                destinationPort: 443,
                networkProtocol: .tcp
            ),
            .allow(matchedRuleId: "stale")
        )

        let rule = ManifestRule(
            id: "r-fresh",
            schemaVersion: 1,
            createdAt: "2026-05-11T00:00:00Z",
            description: nil,
            match: ManifestRuleMatch(
                host: .single("api.anthropic.com"),
                hostPattern: nil,
                port: .single(443),
                protocolName: "tcp"
            ),
            scope: ManifestRuleScope(agentIds: nil, templateIds: nil),
            disposition: "allow",
            timeWindow: nil
        )
        let signed = try makeSignedManifestUpdatedBody(rules: [rule])
        let snapshot = IPCBridgeNotifications.applyManifestUpdated(
            message: .manifestUpdated(signed.body),
            store: store,
            cache: cache,
            pinnedPublicKey: signed.publicKey
        )

        XCTAssertNotNil(snapshot)
        XCTAssertEqual(snapshot?.signatureB64url, signed.body.manifestSignatureB64url)
        XCTAssertEqual(snapshot?.rules.count, 1)
        XCTAssertEqual(store.currentSnapshot()?.signatureB64url, signed.body.manifestSignatureB64url)
        XCTAssertEqual(cache.count, 0)
    }

    func testApplyManifestUpdatedRejectsInvalidSignatureAndKeepsPriorSnapshot() throws {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let rule = ManifestRule(
            id: "r-valid",
            schemaVersion: 1,
            createdAt: "2026-05-11T00:00:00Z",
            description: nil,
            match: ManifestRuleMatch(
                host: .single("api.anthropic.com"),
                hostPattern: nil,
                port: .single(443),
                protocolName: "tcp"
            ),
            scope: ManifestRuleScope(agentIds: nil, templateIds: nil),
            disposition: "allow",
            timeWindow: nil
        )
        let signed = try makeSignedManifestUpdatedBody(rules: [rule])
        XCTAssertNotNil(IPCBridgeNotifications.applyManifestUpdated(
            message: .manifestUpdated(signed.body),
            store: store,
            cache: cache,
            pinnedPublicKey: signed.publicKey
        ))

        let badSignature = ManifestSignatureEnvelope(
            signatureScheme: CastleWallConstants.signatureSchemeV1,
            signingKeyId: "test-key",
            signatureB64url: Base64URL.encode(Data(repeating: 1, count: 64))
        )
        let tampered = ManifestUpdatedBody(
            manifest: signed.body.manifest!,
            signature: badSignature,
            rules: []
        )
        let rejected = IPCBridgeNotifications.applyManifestUpdated(
            message: .manifestUpdated(tampered),
            store: store,
            cache: cache,
            pinnedPublicKey: signed.publicKey
        )
        XCTAssertNil(rejected)
        XCTAssertEqual(store.currentRules().map(\.id), ["r-valid"])
    }

    func testRecoverPersistedManifestRestoresLastValidSnapshot() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathComponent("last-valid-manifest.json")
        let store = ManifestStore(lastValidManifestURL: url)
        let cache = FlowCache(capacity: 8)
        let rule = ManifestRule(
            id: "r-persisted",
            schemaVersion: 1,
            createdAt: "2026-05-11T00:00:00Z",
            description: nil,
            match: ManifestRuleMatch(
                host: .single("api.anthropic.com"),
                hostPattern: nil,
                port: .single(443),
                protocolName: "tcp"
            ),
            scope: ManifestRuleScope(agentIds: nil, templateIds: nil),
            disposition: "allow",
            timeWindow: nil
        )
        let signed = try makeSignedManifestUpdatedBody(rules: [rule])
        XCTAssertNotNil(IPCBridgeNotifications.applyManifestUpdated(
            message: .manifestUpdated(signed.body),
            store: store,
            cache: cache,
            pinnedPublicKey: signed.publicKey
        ))

        let restartedStore = ManifestStore(lastValidManifestURL: url)
        let recovered = IPCBridgeNotifications.recoverPersistedManifest(
            store: restartedStore,
            cache: FlowCache(capacity: 8),
            pinnedPublicKey: signed.publicKey
        )
        XCTAssertNotNil(recovered)
        XCTAssertEqual(restartedStore.currentRules().map(\.id), ["r-persisted"])
    }

    func testApplyManifestUpdatedRejectsSchemaVersionDrift() throws {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let rule = ManifestRule(
            id: "r-drift",
            schemaVersion: 1,
            createdAt: "2026-05-11T00:00:00Z",
            description: nil,
            match: ManifestRuleMatch(
                host: .single("api.anthropic.com"),
                hostPattern: nil,
                port: .single(443),
                protocolName: "tcp"
            ),
            scope: ManifestRuleScope(agentIds: nil, templateIds: nil),
            disposition: "allow",
            timeWindow: nil
        )
        let signed = try makeSignedManifestUpdatedBody(rules: [rule], schemaVersion: 99)
        let snapshot = IPCBridgeNotifications.applyManifestUpdated(
            message: .manifestUpdated(signed.body),
            store: store,
            cache: cache,
            pinnedPublicKey: signed.publicKey
        )
        XCTAssertNil(snapshot)
        XCTAssertFalse(store.hasSnapshot)
    }

    func testApplyManifestUpdatedReturnsNilForOtherMessageTypes() {
        let store = ManifestStore()
        let cache = FlowCache(capacity: 8)
        let snapshot = IPCBridgeNotifications.applyManifestUpdated(
            message: .manifestSubscribe(requestId: "x"),
            store: store,
            cache: cache,
            pinnedPublicKey: Data(repeating: 0, count: 32)
        )
        XCTAssertNil(snapshot)
        XCTAssertNil(store.currentSnapshot())
    }
}
