//
// IPCBridgeNotificationsTests.swift
//
// Verify the four new IPC message variants: round-trip the JSON shape,
// confirm the bridge builders produce the expected envelope, and confirm
// `applyManifestUpdated` writes through to ManifestStore + clears
// FlowCache.
//

import XCTest
import CryptoKit
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
        guard case .manifestUpdated(let decodedBody) = decoded else {
            return XCTFail("expected manifest_updated")
        }
        XCTAssertEqual(decodedBody.type, body.type)
        XCTAssertEqual(decodedBody.manifest, body.manifest)
        XCTAssertEqual(decodedBody.signature, body.signature)
        XCTAssertEqual(decodedBody.rules, body.rules)
        XCTAssertEqual(decodedBody.receivedRules?.count, body.rules.count)

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

    // MARK: - agentOrigin signed-envelope plumbing (2026-05-29)

    private func sampleAllowRule() -> ManifestRule {
        return ManifestRule(
            id: "r-origin",
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
    }

    func testSignedAgentOriginRoundTripsAndInstallsOnEngine() throws {
        let wire = AgentOriginWire(
            mode: .uid,
            agentUid: 600,
            systemUidAllowCeiling: 500
        )
        let signed = try makeSignedManifestUpdatedBody(
            rules: [sampleAllowRule()],
            agentOrigin: wire
        )
        let engine = FlowEvaluatorEngine()
        XCTAssertNil(engine.agentOrigin)

        let snapshot = IPCBridgeNotifications.applyManifestUpdated(
            message: .manifestUpdated(signed.body),
            store: engine.manifestStore,
            cache: engine.flowCache,
            pinnedPublicKey: signed.publicKey,
            engine: engine
        )

        XCTAssertNotNil(snapshot)
        XCTAssertEqual(snapshot?.agentOrigin, wire)
        // Installed on the engine for classification.
        XCTAssertEqual(engine.agentOrigin?.mode, .uid)
        XCTAssertEqual(engine.agentOrigin?.agentUid, 600)
        XCTAssertEqual(engine.agentOrigin?.systemUidAllowCeiling, 500)
    }

    func testAbsentAgentOriginIsTolerated_engineStaysClassifyAllAgent() throws {
        // No agent_origin in the signed body: the snapshot carries nil and
        // the engine's retained descriptor stays nil (classify-all-agent).
        let signed = try makeSignedManifestUpdatedBody(rules: [sampleAllowRule()])
        let engine = FlowEvaluatorEngine()
        let snapshot = IPCBridgeNotifications.applyManifestUpdated(
            message: .manifestUpdated(signed.body),
            store: engine.manifestStore,
            cache: engine.flowCache,
            pinnedPublicKey: signed.publicKey,
            engine: engine
        )
        XCTAssertNotNil(snapshot)
        XCTAssertNil(snapshot?.agentOrigin)
        XCTAssertNil(engine.agentOrigin)
    }

    func testAbsentAgentOriginDoesNotClearRetainedDescriptor() throws {
        // Pre-seed retention: an update with NO agent_origin must NOT wipe a
        // previously-installed descriptor (never relax to more-permissive).
        let engine = FlowEvaluatorEngine(
            agentOrigin: AgentOriginDescriptor(mode: .uid, agentUid: 600, systemUidAllowCeiling: 500)
        )
        let signed = try makeSignedManifestUpdatedBody(rules: [sampleAllowRule()])
        _ = IPCBridgeNotifications.applyManifestUpdated(
            message: .manifestUpdated(signed.body),
            store: engine.manifestStore,
            cache: engine.flowCache,
            pinnedPublicKey: signed.publicKey,
            engine: engine
        )
        // Still retained.
        XCTAssertEqual(engine.agentOrigin?.agentUid, 600)
    }

    func testTamperedEnvelopeCarryingAgentOriginIsRejected() throws {
        // An attacker who flips agent_origin AFTER signing must be rejected by
        // the signature check, so the engine never installs the injected
        // descriptor.
        let goodWire = AgentOriginWire(mode: .uid, agentUid: 600, systemUidAllowCeiling: 500)
        let signed = try makeSignedManifestUpdatedBody(
            rules: [sampleAllowRule()],
            agentOrigin: goodWire
        )
        // Verify against a DIFFERENT pinned key => signature mismatch.
        let wrongKey = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
        let engine = FlowEvaluatorEngine()
        let snapshot = IPCBridgeNotifications.applyManifestUpdated(
            message: .manifestUpdated(signed.body),
            store: engine.manifestStore,
            cache: engine.flowCache,
            pinnedPublicKey: wrongKey,
            engine: engine
        )
        XCTAssertNil(snapshot)
        XCTAssertNil(engine.agentOrigin, "rejected envelope must not install agent_origin")
    }

    // MARK: - S5-0 HIGH-1: malformed gate_uid fails manifest application,
    // keeps prior policy (defense-in-depth at the enforcement boundary).
    //
    // A VALID signature proves the body is AUTHENTIC, not that the producer's
    // floor invariants hold. Each case below signs a well-formed envelope
    // (real signature, correct pinned key) whose `agent_origin` carries an
    // IMPOSSIBLE security state. The enforcement side must reject the WHOLE
    // snapshot and leave the prior good snapshot + classifier untouched.

    /// A gate-uid-scoped allow rule for `host` (S5-0 `scope.uids` axis).
    private func gateScopedRule(uid: UInt32, host: String) -> ManifestRule {
        return ManifestRule(
            id: "gate-scoped",
            schemaVersion: 1,
            createdAt: "2026-07-14T00:00:00Z",
            description: nil,
            match: ManifestRuleMatch(
                host: .single(host),
                hostPattern: nil,
                port: .single(443),
                protocolName: "tcp"
            ),
            scope: ManifestRuleScope(agentIds: nil, templateIds: nil, uids: [uid]),
            disposition: "allow",
            timeWindow: nil
        )
    }

    /// Establish a prior GOOD policy (valid uid origin + a benign rule) on a
    /// fresh engine, so a subsequent malformed manifest's rejection can be
    /// proven to leave this intact.
    private func seedGoodUidPolicy() throws -> FlowEvaluatorEngine {
        let engine = FlowEvaluatorEngine()
        let goodWire = AgentOriginWire(mode: .uid, agentUid: 600, systemUidAllowCeiling: 500)
        let good = try makeSignedManifestUpdatedBody(
            rules: [sampleAllowRule()],
            agentOrigin: goodWire
        )
        XCTAssertNotNil(
            IPCBridgeNotifications.applyManifestUpdated(
                message: .manifestUpdated(good.body),
                store: engine.manifestStore,
                cache: engine.flowCache,
                pinnedPublicKey: good.publicKey,
                engine: engine
            )
        )
        XCTAssertEqual(engine.agentOrigin?.agentUid, 600)
        XCTAssertNil(engine.agentOrigin?.gateUid)
        XCTAssertEqual(engine.manifestStore.currentRules().map { $0.id }, ["r-origin"])
        return engine
    }

    /// Apply a validly-signed but malformed-`agent_origin` manifest and assert
    /// it is rejected whole and the prior good policy survives unchanged.
    private func assertMalformedOriginRejectedKeepingPrior(
        badWire: AgentOriginWire,
        badRules: [ManifestRule],
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let engine = try seedGoodUidPolicy()
        let bad = try makeSignedManifestUpdatedBody(rules: badRules, agentOrigin: badWire)
        let rejected = IPCBridgeNotifications.applyManifestUpdated(
            message: .manifestUpdated(bad.body),
            store: engine.manifestStore,
            cache: engine.flowCache,
            pinnedPublicKey: bad.publicKey,
            engine: engine
        )
        XCTAssertNil(rejected, "malformed agent_origin must reject the whole snapshot", file: file, line: line)
        // Prior classifier intact: still the good agent uid, still no gate uid.
        XCTAssertEqual(engine.agentOrigin?.agentUid, 600, file: file, line: line)
        XCTAssertNil(engine.agentOrigin?.gateUid, file: file, line: line)
        // Prior rules intact: the malformed manifest's rules never went live.
        XCTAssertEqual(engine.manifestStore.currentRules().map { $0.id }, ["r-origin"], file: file, line: line)
    }

    func testMalformedGateUid_collisionWithAgentUid_rejectsAndKeepsPrior() throws {
        // The exact Codex exploit: gate_uid == agent_uid (600) plus a rule
        // scoped uids=[600]. If accepted, the agent uid would use a rule meant
        // for the distinct gate uid -- the two principals collapse into one.
        try assertMalformedOriginRejectedKeepingPrior(
            badWire: AgentOriginWire(mode: .uid, agentUid: 600, gateUid: 600, systemUidAllowCeiling: 500),
            badRules: [gateScopedRule(uid: 600, host: "gate-endpoint.example.com")]
        )
    }

    func testMalformedGateUid_root_rejectsAndKeepsPrior() throws {
        try assertMalformedOriginRejectedKeepingPrior(
            badWire: AgentOriginWire(mode: .uid, agentUid: 600, gateUid: 0, systemUidAllowCeiling: 500),
            badRules: [sampleAllowRule()]
        )
    }

    func testMalformedGateUid_belowCeiling_rejectsAndKeepsPrior() throws {
        try assertMalformedOriginRejectedKeepingPrior(
            badWire: AgentOriginWire(mode: .uid, agentUid: 600, gateUid: 100, systemUidAllowCeiling: 500),
            badRules: [sampleAllowRule()]
        )
    }

    func testMalformedAgentUid_belowCeiling_rejectsAndKeepsPrior() throws {
        // The agent uid floor is re-validated at the boundary too (not just
        // gate_uid): a sub-ceiling agent uid is impossible security state.
        try assertMalformedOriginRejectedKeepingPrior(
            badWire: AgentOriginWire(mode: .uid, agentUid: 100, systemUidAllowCeiling: 500),
            badRules: [sampleAllowRule()]
        )
    }

    func testNatDescriptorCarryingGateUid_rejectsNotSilentlyDropped() throws {
        // Never-silently-degrade: TS refuses to sign a NAT descriptor carrying
        // gate_uid; the enforcement side must REJECT the whole snapshot too,
        // not silently drop the field (which the wire->descriptor converter
        // would otherwise do by construction).
        try assertMalformedOriginRejectedKeepingPrior(
            badWire: AgentOriginWire(
                mode: .nat,
                egressHelperSigningId: "ai.sanctuaryprotocol.egress-helper",
                gateUid: 601,
                systemUidAllowCeiling: 500
            ),
            badRules: [sampleAllowRule()]
        )
    }

    func testMalformedGateUidCollision_exploitFlowNotAllowedPriorPolicyEnforced() throws {
        // End-to-end proof the exploit does not land: after the collision
        // manifest is rejected, an agent-uid flow (ruid 600) to the gate
        // endpoint is NOT allowed -- the prior policy (which has no rule for
        // that host) default-denies it. The second principal never collapsed
        // into the first because the malformed manifest never went live.
        let engine = try seedGoodUidPolicy()
        let bad = try makeSignedManifestUpdatedBody(
            rules: [gateScopedRule(uid: 600, host: "gate-endpoint.example.com")],
            agentOrigin: AgentOriginWire(mode: .uid, agentUid: 600, gateUid: 600, systemUidAllowCeiling: 500)
        )
        XCTAssertNil(
            IPCBridgeNotifications.applyManifestUpdated(
                message: .manifestUpdated(bad.body),
                store: engine.manifestStore,
                cache: engine.flowCache,
                pinnedPublicKey: bad.publicKey,
                engine: engine
            )
        )
        let agentFlow = FilterFlowDescriptor(
            sourceAppIdentifier: "deadbeef",
            agentId: "deadbeef",
            templateId: "unknown",
            destinationHost: "gate-endpoint.example.com",
            destinationIp: "104.18.32.10",
            destinationPort: 443,
            networkProtocol: .tcp,
            hostnameSource: "sni",
            opaqueDestination: false,
            sourceRuid: 600,
            sourcePid: 4242,
            sourcePidVersion: 1,
            sourceSigningId: nil,
            sourceTeamId: nil,
            sourceUnattributed: false
        )
        XCTAssertEqual(engine.evaluate(agentFlow), .drop(matchedRuleId: nil))
    }

    // MARK: - PR-905-review BLOCKER: install ordering closes the boot window

    func testApplyManifestUpdated_installsOriginBEFORE_rulesGoLive() throws {
        // BLOCKER regression: provisioned allow rules must NEVER be evaluable
        // while `_agentOrigin` is still nil. `store.update` fires its observers
        // the instant the new rules become the live snapshot; capture the
        // engine's origin AT THAT MOMENT and assert it is already installed.
        // Before the reorder fix, the origin was installed AFTER store.update,
        // so this observer would have seen a nil origin with live allow rules
        // (the fail-open window the `== .uid` predicate then walked into).
        let wire = AgentOriginWire(mode: .uid, agentUid: 600, systemUidAllowCeiling: 500)
        let signed = try makeSignedManifestUpdatedBody(
            rules: [sampleAllowRule()],
            agentOrigin: wire
        )
        let engine = FlowEvaluatorEngine()

        var originAtRulesLive: AgentOriginDescriptor??
        var ruleCountAtObserve = -1
        _ = engine.manifestStore.addObserver { snapshot in
            originAtRulesLive = engine.agentOrigin
            ruleCountAtObserve = snapshot.rules.count
        }

        let snapshot = IPCBridgeNotifications.applyManifestUpdated(
            message: .manifestUpdated(signed.body),
            store: engine.manifestStore,
            cache: engine.flowCache,
            pinnedPublicKey: signed.publicKey,
            engine: engine
        )
        XCTAssertNotNil(snapshot)
        // The observer fired with the new rules live...
        XCTAssertEqual(ruleCountAtObserve, 1)
        // ...and the origin was ALREADY installed at that exact point (no
        // nil-origin-with-live-allow-rules window).
        XCTAssertEqual(originAtRulesLive??.mode, .uid)
        XCTAssertEqual(originAtRulesLive??.agentUid, 600)
    }

    func testRecoverPersistedManifest_installsOriginBEFORE_rulesGoLive() throws {
        // Same window on the RESTART-recovery path (the one that runs on every
        // boot). Persist a uid-mode manifest, then recover it into a fresh
        // engine and assert the origin is installed by the time the recovered
        // rules go live.
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathComponent("last-valid-manifest.json")
        let wire = AgentOriginWire(mode: .uid, agentUid: 600, systemUidAllowCeiling: 500)
        let signed = try makeSignedManifestUpdatedBody(
            rules: [sampleAllowRule()],
            agentOrigin: wire
        )
        let seedStore = ManifestStore(lastValidManifestURL: url)
        XCTAssertNotNil(IPCBridgeNotifications.applyManifestUpdated(
            message: .manifestUpdated(signed.body),
            store: seedStore,
            cache: FlowCache(capacity: 8),
            pinnedPublicKey: signed.publicKey
        ))

        let restartedEngine = FlowEvaluatorEngine(
            manifestStore: ManifestStore(lastValidManifestURL: url)
        )
        var originAtRulesLive: AgentOriginDescriptor??
        var ruleCountAtObserve = -1
        _ = restartedEngine.manifestStore.addObserver { snapshot in
            originAtRulesLive = restartedEngine.agentOrigin
            ruleCountAtObserve = snapshot.rules.count
        }

        let recovered = IPCBridgeNotifications.recoverPersistedManifest(
            store: restartedEngine.manifestStore,
            cache: restartedEngine.flowCache,
            pinnedPublicKey: signed.publicKey,
            engine: restartedEngine
        )
        XCTAssertNotNil(recovered)
        XCTAssertEqual(ruleCountAtObserve, 1)
        XCTAssertEqual(originAtRulesLive??.mode, .uid)
        XCTAssertEqual(originAtRulesLive??.agentUid, 600)
    }

    func testUnusableAgentOriginRejectsWholeSnapshotFailClosed() throws {
        // A signed-but-structurally-unusable UID descriptor (no agent_uid).
        //
        // HARDENED (S5-0 HIGH-1, 2026-07-14): the OLD behavior tolerated this
        // -- it applied the snapshot (rules went live) while merely skipping
        // the descriptor install. But malformed descriptor + live rules is NOT
        // a closed state (a signed body proves authenticity, not producer
        // validity). The enforcement boundary now REJECTS THE WHOLE SNAPSHOT
        // and keeps prior policy: the engine stays classify-all-agent and NO
        // rules go live.
        let badWire = AgentOriginWire(mode: .uid, agentUid: nil, systemUidAllowCeiling: 500)
        let signed = try makeSignedManifestUpdatedBody(
            rules: [sampleAllowRule()],
            agentOrigin: badWire
        )
        let engine = FlowEvaluatorEngine()
        let snapshot = IPCBridgeNotifications.applyManifestUpdated(
            message: .manifestUpdated(signed.body),
            store: engine.manifestStore,
            cache: engine.flowCache,
            pinnedPublicKey: signed.publicKey,
            engine: engine
        )
        XCTAssertNil(snapshot, "unusable descriptor must reject the whole snapshot")
        XCTAssertNil(engine.agentOrigin, "unusable descriptor must not install")
        XCTAssertTrue(engine.manifestStore.currentRules().isEmpty, "no rules go live on a rejected manifest")
    }

    func testVerifiedSnapshotThrowsTypedErrorOnGateUidCollision() throws {
        // Pin the typed error at the verifier chokepoint (both apply and
        // recover paths funnel through it and keep prior policy on throw).
        let badWire = AgentOriginWire(mode: .uid, agentUid: 600, gateUid: 600, systemUidAllowCeiling: 500)
        let signed = try makeSignedManifestUpdatedBody(
            rules: [sampleAllowRule()],
            agentOrigin: badWire
        )
        XCTAssertThrowsError(
            try SignedManifestVerifier.verifiedSnapshot(
                from: signed.body,
                pinnedPublicKey: signed.publicKey
            )
        ) { error in
            guard case SignedManifestVerificationError.invalidAgentOrigin = error else {
                return XCTFail("expected .invalidAgentOrigin, got \(error)")
            }
        }
    }
}
