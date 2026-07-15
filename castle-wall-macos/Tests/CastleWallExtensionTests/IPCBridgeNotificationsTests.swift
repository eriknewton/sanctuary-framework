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

    // MARK: - S5-0 HIGH-2: signed rule with off-spec RAW scope fails whole
    // snapshot, keeps prior policy (the digest binds RAW bytes; optional
    // Codable must not silently collapse null/wrong-type to "absent" = all).

    private func validGateOrigin() -> AgentOriginWire {
        return AgentOriginWire(mode: .uid, agentUid: 600, gateUid: 601, systemUidAllowCeiling: 500)
    }

    /// A raw rule JSON string for gate-endpoint.example.com:443 with the given
    /// literal `scope` JSON substring.
    private func rawGateRule(scopeJSON: String) -> String {
        return """
        {"id":"gate-scoped","schema_version":1,"created_at":"2026-07-14T00:00:00Z",\
        "match":{"host":["gate-endpoint.example.com"],"port":[443],"protocol":"tcp"},\
        "scope":\(scopeJSON),"disposition":"allow"}
        """
    }

    private func assertRawScopeRejectedKeepingPrior(
        scopeJSON: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let engine = try seedGoodUidPolicy()
        let bad = try makeSignedBodyWithRawRules(
            rawRuleJSONs: [rawGateRule(scopeJSON: scopeJSON)],
            agentOrigin: validGateOrigin()
        )
        let rejected = IPCBridgeNotifications.applyManifestUpdated(
            message: .manifestUpdated(bad.body),
            store: engine.manifestStore,
            cache: engine.flowCache,
            pinnedPublicKey: bad.publicKey,
            engine: engine
        )
        XCTAssertNil(rejected, "off-spec raw scope must reject the whole snapshot", file: file, line: line)
        XCTAssertEqual(engine.agentOrigin?.agentUid, 600, file: file, line: line)
        XCTAssertEqual(engine.manifestStore.currentRules().map { $0.id }, ["r-origin"], file: file, line: line)
    }

    func testSignedScopeUidsNull_theExploit_rejectsWholeSnapshotKeepsPrior() throws {
        // Codex's exact HIGH-2 repro: raw `scope: {"uids": null}`. Optional
        // Codable collapses it to uids == nil, which scopeMatches would treat
        // as "all agents" -- widening a gate-only rule to every principal.
        try assertRawScopeRejectedKeepingPrior(scopeJSON: #"{"uids":null}"#)
    }

    func testVerifiedSnapshotThrowsInvalidRuleSchemaForScopeUidsNull() throws {
        // Pin the typed error + the "does not throw" repro Codex ran directly
        // at the verifier chokepoint.
        let bad = try makeSignedBodyWithRawRules(
            rawRuleJSONs: [rawGateRule(scopeJSON: #"{"uids":null}"#)],
            agentOrigin: validGateOrigin()
        )
        XCTAssertThrowsError(
            try SignedManifestVerifier.verifiedSnapshot(from: bad.body, pinnedPublicKey: bad.publicKey)
        ) { error in
            guard case SignedManifestVerificationError.invalidRuleSchema = error else {
                return XCTFail("expected .invalidRuleSchema, got \(error)")
            }
        }
    }

    func testSignedScopeUidsZeroRoot_rejects() throws {
        // `[0]` passes the typed `[UInt32]` decode (0 is a valid UInt32) but is
        // off-spec (uids must be >= 1) -- so it reaches and is caught by the
        // raw-schema chokepoint, not the typed decoder.
        try assertRawScopeRejectedKeepingPrior(scopeJSON: #"{"uids":[0]}"#)
    }

    func testSignedScopeAgentIdsNull_rejects() throws {
        // Same collapse class on the agent_ids axis (also touched by S5-0).
        try assertRawScopeRejectedKeepingPrior(scopeJSON: #"{"agent_ids":null}"#)
    }

    func testSignedScopeTemplateIdsNull_rejects() throws {
        try assertRawScopeRejectedKeepingPrior(scopeJSON: #"{"template_ids":null}"#)
    }

    // The two-layer defense: shapes that optional Codable does NOT silently
    // collapse (a scalar where an array is expected, a fractional/negative/
    // over-UInt32 uid, a non-string id) are rejected even earlier -- by the
    // strict typed `[UInt32]?` / `[String]?` decode of `ManifestRule` -- so the
    // whole IPC message fails to decode and never reaches `applyManifestUpdated`
    // at all. This proves that first line (the wire body cannot be built).
    func testOffSpecScopeShapesFailClosedAtStrictTypedDecode() throws {
        for scopeJSON in [
            #"{"uids":601}"#,          // scalar, not array
            #"{"uids":[601.5]}"#,      // fractional
            #"{"uids":[-1]}"#,         // negative (not UInt32-representable)
            #"{"uids":[4294967296]}"#, // above UInt32.max
            #"{"template_ids":[123]}"#, // non-string id
        ] {
            XCTAssertThrowsError(
                try makeSignedBodyWithRawRules(
                    rawRuleJSONs: [rawGateRule(scopeJSON: scopeJSON)],
                    agentOrigin: validGateOrigin()
                ),
                "off-spec scope \(scopeJSON) must fail closed at IPC decode"
            )
        }
    }

    // The raw-schema chokepoint's own range/shape logic, exercised DIRECTLY
    // (bypassing the strict typed decode that would otherwise pre-empt some of
    // these) so the chokepoint is a proven backstop even if the typed layer
    // ever loosens. Each off-spec raw `scope.uids` throws `.invalidRuleSchema`.
    func testValidateRawScope_rejectsEveryOffSpecUidsShape() throws {
        let badUids: [JSONValue] = [
            .null,                                   // null (Codable-collapse class)
            .integer(601),                           // scalar, not array
            .string("601"),                          // string, not array
            .array([.number(601.5)]),                // fractional element
            .array([.integer(0)]),                   // zero / root
            .array([.integer(-1)]),                  // negative
            .array([.integer(0x1_0000_0000)]),       // above UInt32.max
            .array([.string("601")]),                // string element
        ]
        for uids in badUids {
            XCTAssertThrowsError(
                try SignedManifestVerifier.validateRawScope(.object(["uids": uids]), ruleId: "r")
            ) { error in
                guard case SignedManifestVerificationError.invalidRuleSchema = error else {
                    return XCTFail("expected .invalidRuleSchema for \(uids), got \(error)")
                }
            }
        }
        // Control: a well-formed array and an empty array (means "all") pass.
        XCTAssertNoThrow(
            try SignedManifestVerifier.validateRawScope(
                .object(["uids": .array([.integer(601), .integer(602)])]), ruleId: "r"
            )
        )
        XCTAssertNoThrow(
            try SignedManifestVerifier.validateRawScope(.object(["uids": .array([])]), ruleId: "r")
        )
        // Control: unknown scope key rejected (an unknown-only scope axis would
        // decode to no known axes and widen to all-agents).
        XCTAssertThrowsError(
            try SignedManifestVerifier.validateRawScope(.object(["future_axis": .string("x")]), ruleId: "r")
        )
    }

    func testValidateRawScope_rejectsNonStringIdAxes() throws {
        for axis in ["agent_ids", "template_ids"] {
            for bad: JSONValue in [.null, .string("x"), .array([.integer(1)]), .array([.string("")])] {
                XCTAssertThrowsError(
                    try SignedManifestVerifier.validateRawScope(.object([axis: bad]), ruleId: "r")
                ) { error in
                    guard case SignedManifestVerificationError.invalidRuleSchema = error else {
                        return XCTFail("expected .invalidRuleSchema for \(axis)=\(bad), got \(error)")
                    }
                }
            }
        }
    }

    func testValidateRawMatch_mirrorsTsValidateRule() throws {
        // Each off-spec match shape throws (HIGH-3 completeness).
        let badMatches: [JSONValue] = [
            .object([:]),                                             // no destination axis
            .object(["host": .null]),                                // host null (collapse)
            .object(["host": .array([])]),                           // empty array
            .object(["host": .array([.string("")])]),                // empty-string element
            .object(["host_pattern": .string("")]),                  // empty pattern
            .object(["host_pattern": .array([.string("x")])]),       // pattern must be scalar
            .object(["ip": .string("not-an-ip")]),                   // malformed IP
            .object(["cidr": .string("10.0.0.0/99")]),               // bad prefix
            .object(["port": .null]),                                // port null (collapse)
            .object(["port": .integer(0)]),                          // port out of range
            .object(["port": .integer(70000)]),                      // port out of range
            .object(["port": .array([])]),                           // empty port array
            .object(["host": .string("x"), "protocol": .null]),      // protocol null
            .object(["host": .string("x"), "protocol": .string("icmp")]), // bad protocol
            .object(["host": .string("x"), "future_axis": .string("y")]), // unknown match key
        ]
        for match in badMatches {
            XCTAssertThrowsError(
                try SignedManifestVerifier.validateRawMatch(match, ruleId: "r")
            ) { error in
                guard case SignedManifestVerificationError.invalidRuleSchema = error else {
                    return XCTFail("expected .invalidRuleSchema for \(match), got \(error)")
                }
            }
        }
        // Controls: legitimate match shapes pass.
        for good: JSONValue in [
            .object(["host": .string("api.anthropic.com"), "port": .integer(443), "protocol": .string("tcp")]),
            .object(["host": .array([.string("a.com"), .string("b.com")])]),
            .object(["ip": .string("1.1.1.1")]),
            .object(["cidr": .string("10.0.0.0/8")]),
            .object(["port": .array([.integer(80), .integer(443)])]),
            .object(["host_pattern": .string("*.example.com")]),
        ] {
            XCTAssertNoThrow(
                try SignedManifestVerifier.validateRawMatch(good, ruleId: "r"),
                "legitimate match \(good) must pass"
            )
        }
    }

    func testSignedScopeUidsValidArray_stillAccepted() throws {
        // Control: a well-formed raw uids scope is NOT rejected -- the
        // chokepoint rejects only off-spec shapes, never legitimate ones.
        let engine = try seedGoodUidPolicy()
        let good = try makeSignedBodyWithRawRules(
            rawRuleJSONs: [rawGateRule(scopeJSON: #"{"uids":[601]}"#)],
            agentOrigin: validGateOrigin()
        )
        let snapshot = IPCBridgeNotifications.applyManifestUpdated(
            message: .manifestUpdated(good.body),
            store: engine.manifestStore,
            cache: engine.flowCache,
            pinnedPublicKey: good.publicKey,
            engine: engine
        )
        XCTAssertNotNil(snapshot, "a well-formed uids-scoped rule must still apply")
        XCTAssertEqual(engine.manifestStore.currentRules().map { $0.id }, ["gate-scoped"])
        // And the gate-scoped rule does not leak to the agent uid.
        XCTAssertEqual(snapshot?.rules.first?.scope.uids, [601])
    }

    func testSignedScopeUidsNull_exploitFlowNotAllowed_agentDefaultDenied() throws {
        // End-to-end: after the null-scope manifest is rejected, an agent-uid
        // (600) flow to the gate endpoint default-denies under the prior policy.
        // The rule never widened to all agents because it never went live.
        let engine = try seedGoodUidPolicy()
        let bad = try makeSignedBodyWithRawRules(
            rawRuleJSONs: [rawGateRule(scopeJSON: #"{"uids":null}"#)],
            agentOrigin: validGateOrigin()
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

    func testValidateRawAgentOriginShape_rejectsNullUidField() throws {
        // Defense-in-depth (S5-0 HIGH-2 class) on the raw agent_origin: a
        // uid-family field present as explicit null (which optional Codable
        // would collapse to absent) is rejected against the raw JSON.
        let rawManifest = JSONValue.object([
            "agent_origin": .object([
                "mode": .string("uid"),
                "agent_uid": .null, // explicit null -> would collapse to nil
                "system_uid_allow_ceiling": .integer(500),
            ]),
        ])
        XCTAssertThrowsError(
            try SignedManifestVerifier.validateRawAgentOriginShape(rawManifest)
        ) { error in
            guard case SignedManifestVerificationError.invalidAgentOrigin = error else {
                return XCTFail("expected .invalidAgentOrigin, got \(error)")
            }
        }
        // Control: a clean integer descriptor passes the raw shape check.
        XCTAssertNoThrow(
            try SignedManifestVerifier.validateRawAgentOriginShape(
                .object([
                    "agent_origin": .object([
                        "mode": .string("uid"),
                        "agent_uid": .integer(600),
                        "gate_uid": .integer(601),
                        "system_uid_allow_ceiling": .integer(500),
                    ]),
                ])
            )
        )
        // Control: absent / null agent_origin is fine (means no descriptor).
        XCTAssertNoThrow(try SignedManifestVerifier.validateRawAgentOriginShape(.object([:])))
        XCTAssertNoThrow(try SignedManifestVerifier.validateRawAgentOriginShape(.object(["agent_origin": .null])))
    }

    // MARK: - S5-0 HIGH-4: NAT helper identity strings must be non-empty
    // (an empty string makes the REAL helper classify as operator and bypass
    // every rule via the allow-all fast-path).

    func testNatEmptySigningId_rejectsAndKeepsPrior() throws {
        try assertMalformedOriginRejectedKeepingPrior(
            badWire: AgentOriginWire(mode: .nat, egressHelperSigningId: "", systemUidAllowCeiling: 500),
            badRules: [sampleAllowRule()]
        )
    }

    func testNatEmptyTeamId_rejectsAndKeepsPrior() throws {
        try assertMalformedOriginRejectedKeepingPrior(
            badWire: AgentOriginWire(mode: .nat, egressHelperTeamId: "", systemUidAllowCeiling: 500),
            badRules: [sampleAllowRule()]
        )
    }

    func testNatValidSigningPlusEmptyTeam_rejectsAndKeepsPrior() throws {
        // One valid axis plus one present-but-empty axis still rejects: a
        // present helper identity must be non-empty (TS treats "" as absent,
        // Swift must not accept it as a match target).
        try assertMalformedOriginRejectedKeepingPrior(
            badWire: AgentOriginWire(
                mode: .nat,
                egressHelperSigningId: "ai.sanctuaryprotocol.egress-helper",
                egressHelperTeamId: "",
                systemUidAllowCeiling: 500
            ),
            badRules: [sampleAllowRule()]
        )
    }

    func testNatEmptySigningId_realHelperNotFastPathedAfterRejection() throws {
        // End-to-end HIGH-4 proof: after the empty-signing-id NAT descriptor is
        // rejected, the prior UID-mode policy stays in force; a flow from the
        // agent uid to a non-allowlisted host default-denies (the empty-helper
        // descriptor, which would have operator-fast-pathed the real helper,
        // never went live).
        let engine = try seedGoodUidPolicy()
        let bad = try makeSignedManifestUpdatedBody(
            rules: [sampleAllowRule()],
            agentOrigin: AgentOriginWire(mode: .nat, egressHelperSigningId: "", systemUidAllowCeiling: 500)
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
        // Prior uid-mode classifier intact.
        XCTAssertEqual(engine.agentOrigin?.mode, .uid)
        XCTAssertEqual(engine.agentOrigin?.agentUid, 600)
    }

    // MARK: - S5-0 HIGH-5: unenforceable-axis (time_window) fail-closed gate.
    // TS accepts time_window (schema.ts:216) but the macOS evaluator does not
    // enforce it, so a time-bounded allow would become an all-time allow. The
    // verifier rejects it fail-closed, matching the Linux daemon's
    // UnenforceableRuleAxis. This is DISTINCT from schema validation: it rejects
    // a field the evaluator does NOT consume (vs. validating one it does).

    func testUnenforceableAxis_timeWindow_rejectsWholeSnapshotKeepsPrior() throws {
        // Codex's exact repro shape: a validly-signed windowed allow.
        try assertRawRuleRejectedKeepingPrior(
            #"""
            {"id":"windowed","schema_version":1,"created_at":"2026-07-14T00:00:00Z","match":{"host":"windowed.example.com","port":443,"protocol":"tcp"},"scope":{"uids":[601]},"disposition":"allow","time_window":{"start":"09:00","end":"17:00"}}
            """#
        )
    }

    func testUnenforceableAxis_timeWindow_throwsTypedUnenforceableError() throws {
        let bad = try makeSignedBodyWithRawRules(
            rawRuleJSONs: [
                #"""
                {"id":"windowed","schema_version":1,"created_at":"2026-07-14T00:00:00Z","match":{"host":"windowed.example.com","port":443,"protocol":"tcp"},"scope":{"uids":[601]},"disposition":"allow","time_window":{"start":"09:00","end":"17:00"}}
                """#
            ],
            agentOrigin: validGateOrigin()
        )
        XCTAssertThrowsError(
            try SignedManifestVerifier.verifiedSnapshot(from: bad.body, pinnedPublicKey: bad.publicKey)
        ) { error in
            guard case SignedManifestVerificationError.unenforceableRuleAxis(_, let axis) = error else {
                return XCTFail("expected .unenforceableRuleAxis, got \(error)")
            }
            XCTAssertEqual(axis, "time_window")
        }
    }

    func testUnenforceableAxis_timeWindow_windowedHostNotReachableAfterRejection() throws {
        // End-to-end: seed a two-uid policy that CONFINES the gate uid 601 (so
        // 601 is a confined principal, not an operator), then apply a windowed
        // allow for the gate to windowed.example.com. It is rejected; the prior
        // policy (which has no rule for that host) stands, so the gate uid flow
        // to the windowed host default-denies. Had the windowed rule been
        // accepted, the evaluator -- which ignores time_window -- would have
        // ALLOWED it at all times (the HIGH-5 widening).
        let engine = FlowEvaluatorEngine()
        let seedWire = AgentOriginWire(mode: .uid, agentUid: 600, gateUid: 601, systemUidAllowCeiling: 500)
        let seed = try makeSignedManifestUpdatedBody(rules: [sampleAllowRule()], agentOrigin: seedWire)
        XCTAssertNotNil(IPCBridgeNotifications.applyManifestUpdated(
            message: .manifestUpdated(seed.body),
            store: engine.manifestStore, cache: engine.flowCache,
            pinnedPublicKey: seed.publicKey, engine: engine
        ))
        XCTAssertEqual(engine.agentOrigin?.gateUid, 601)

        let bad = try makeSignedBodyWithRawRules(
            rawRuleJSONs: [
                #"""
                {"id":"windowed","schema_version":1,"created_at":"2026-07-14T00:00:00Z","match":{"host":"windowed.example.com","port":443,"protocol":"tcp"},"scope":{"uids":[601]},"disposition":"allow","time_window":{"start":"09:00","end":"17:00"}}
                """#
            ],
            agentOrigin: seedWire
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
        // Prior gate-confining policy intact; the windowed rule never went live.
        XCTAssertEqual(engine.agentOrigin?.gateUid, 601)
        XCTAssertEqual(engine.manifestStore.currentRules().map { $0.id }, ["r-origin"])

        let gateFlow = FilterFlowDescriptor(
            sourceAppIdentifier: "deadbeef",
            agentId: "deadbeef",
            templateId: "unknown",
            destinationHost: "windowed.example.com",
            destinationIp: "104.18.32.10",
            destinationPort: 443,
            networkProtocol: .tcp,
            hostnameSource: "sni",
            opaqueDestination: false,
            sourceRuid: 601,
            sourcePid: 4242,
            sourcePidVersion: 1,
            sourceSigningId: nil,
            sourceTeamId: nil,
            sourceUnattributed: false
        )
        XCTAssertEqual(engine.evaluate(gateFlow), .drop(matchedRuleId: nil))
    }

    // MARK: - S5-0_930 anti-regression PARITY test
    //
    // Enumerates every security-relevant field TS `validateRule` +
    // `validateAgentOrigin` validate and asserts the Swift chokepoint rejects a
    // malformed raw value for each -- rejecting the WHOLE snapshot and keeping
    // prior policy. This is what makes the chokepoint provably COMPLETE: if a
    // future change drops a field from `validateSignedRule`, the matching row
    // here fails. Each raw rule below is otherwise well-formed except the one
    // field under test.

    /// Seed prior good policy, sign+apply a manifest carrying the given single
    /// raw rule, and assert it rejects the whole snapshot + keeps prior policy.
    private func assertRawRuleRejectedKeepingPrior(
        _ ruleJSON: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let engine = try seedGoodUidPolicy()
        let bad = try makeSignedBodyWithRawRules(rawRuleJSONs: [ruleJSON], agentOrigin: validGateOrigin())
        let rejected = IPCBridgeNotifications.applyManifestUpdated(
            message: .manifestUpdated(bad.body),
            store: engine.manifestStore,
            cache: engine.flowCache,
            pinnedPublicKey: bad.publicKey,
            engine: engine
        )
        XCTAssertNil(rejected, "malformed rule must reject the whole snapshot", file: file, line: line)
        XCTAssertEqual(engine.agentOrigin?.agentUid, 600, file: file, line: line)
        XCTAssertEqual(engine.manifestStore.currentRules().map { $0.id }, ["r-origin"], file: file, line: line)
    }

    private func rawRule(match: String, scope: String = #"{"uids":[601]}"#, disposition: String = #""allow""#, extra: String = "") -> String {
        return """
        {"id":"parity","schema_version":1,"created_at":"2026-07-14T00:00:00Z",\
        "match":\(match),"scope":\(scope),"disposition":\(disposition)\(extra)}
        """
    }

    func testS5_0_930_parity_everyTsValidatedRuleFieldRejects() throws {
        // Map: raw rule shape -> TS validateRule source it mirrors.
        let cases: [(String, String)] = [
            // match clause (schema.ts:231-286) -- HIGH-3
            (rawRule(match: #"{}"#), "match >=1 axis (schema.ts:240)"),
            (rawRule(match: #"{"host":null,"port":[443]}"#), "match.host null (schema.ts:245+141)"),
            (rawRule(match: #"{"host":[]}"#), "match.host empty array (schema.ts:148)"),
            (rawRule(match: #"{"host":[""]}"#), "match.host empty element (schema.ts:249)"),
            (rawRule(match: #"{"host_pattern":""}"#), "match.host_pattern empty (schema.ts:254)"),
            (rawRule(match: #"{"ip":"not-an-ip"}"#), "match.ip grammar (schema.ts:261)"),
            (rawRule(match: #"{"cidr":"10.0.0.0/99"}"#), "match.cidr grammar (schema.ts:263)"),
            (rawRule(match: #"{"port":null,"host":"x"}"#), "match.port null (schema.ts:272+141)"),
            (rawRule(match: #"{"port":0}"#), "match.port range (schema.ts:99)"),
            (rawRule(match: #"{"port":70000}"#), "match.port range (schema.ts:99)"),
            (rawRule(match: #"{"host":"x","protocol":null}"#), "match.protocol null (schema.ts:281)"),
            (rawRule(match: #"{"host":"x","protocol":"icmp"}"#), "match.protocol enum (schema.ts:283)"),
            (rawRule(match: #"{"host":"x","future_axis":"y"}"#), "unknown match key (schema.ts:234)"),
            // scope (schema.ts:288-303) -- HIGH-2
            (rawRule(match: #"{"host":"x"}"#, scope: #"{"uids":null}"#), "scope.uids null (schema.ts:299)"),
            (rawRule(match: #"{"host":"x"}"#, scope: #"{"agent_ids":[""]}"#), "scope.agent_ids empty (schema.ts:295)"),
            (rawRule(match: #"{"host":"x"}"#, scope: #"{"future_axis":"y"}"#), "unknown scope key (schema.ts:291)"),
            // disposition (schema.ts:305)
            (rawRule(match: #"{"host":"x"}"#, disposition: #""observe""#), "disposition enum (schema.ts:305)"),
            // unknown rule key (schema.ts:227)
            (rawRule(match: #"{"host":"x"}"#, extra: #","future_field":true"#), "unknown rule key (schema.ts:227)"),
            // UNENFORCEABLE-AXIS gate (HIGH-5) -- NOT a schema-enforcement row:
            // time_window is TS-valid (schema.ts:216) but the macOS evaluator
            // does not enforce it, so a windowed allow must be rejected
            // fail-closed (parity with the Linux daemon's UnenforceableRuleAxis,
            // castle-wall-daemon/src/policy.rs:668). If time-window enforcement is
            // ever wired into AllowlistEvaluator, this row must move/change.
            (
                rawRule(match: #"{"host":"x"}"#, extra: #","time_window":{"start":"09:00","end":"17:00"}"#),
                "time_window unenforceable-axis gate (policy.rs:668; NOT schema.ts:216)"
            ),
        ]
        for (ruleJSON, tsSource) in cases {
            do {
                try assertRawRuleRejectedKeepingPrior(ruleJSON)
            } catch {
                XCTFail("parity row failed for [\(tsSource)]: \(error)\nrule=\(ruleJSON)")
            }
        }
    }

    func testS5_0_930_parity_everyTsValidatedAgentOriginFieldRejects() throws {
        // agent_origin (agent-origin.ts) -- HIGH-1 floors + HIGH-4 helper.
        // uid mode floors:
        try assertMalformedOriginRejectedKeepingPrior(
            badWire: AgentOriginWire(mode: .uid, agentUid: nil, systemUidAllowCeiling: 500),
            badRules: [sampleAllowRule()]) // uid mode requires agent_uid (agent-origin.ts:79)
        try assertMalformedOriginRejectedKeepingPrior(
            badWire: AgentOriginWire(mode: .uid, agentUid: 100, systemUidAllowCeiling: 500),
            badRules: [sampleAllowRule()]) // agent_uid >= ceiling (agent-origin.ts:94)
        try assertMalformedOriginRejectedKeepingPrior(
            badWire: AgentOriginWire(mode: .uid, agentUid: 600, gateUid: 600, systemUidAllowCeiling: 500),
            badRules: [sampleAllowRule()]) // gate_uid != agent_uid (agent-origin.ts:114)
        try assertMalformedOriginRejectedKeepingPrior(
            badWire: AgentOriginWire(mode: .uid, agentUid: 600, gateUid: 100, systemUidAllowCeiling: 500),
            badRules: [sampleAllowRule()]) // gate_uid >= ceiling (agent-origin.ts:112)
        // NAT mode: gate_uid forbidden, >=1 non-empty helper (agent-origin.ts:129,139).
        try assertMalformedOriginRejectedKeepingPrior(
            badWire: AgentOriginWire(mode: .nat, egressHelperSigningId: "id", gateUid: 601, systemUidAllowCeiling: 500),
            badRules: [sampleAllowRule()]) // gate_uid in nat rejected
        try assertMalformedOriginRejectedKeepingPrior(
            badWire: AgentOriginWire(mode: .nat, egressHelperSigningId: "", systemUidAllowCeiling: 500),
            badRules: [sampleAllowRule()]) // empty helper (HIGH-4, agent-origin.ts:139)
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
