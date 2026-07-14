//
// ExtensionDispatcherTests.swift
//
// Covers the Phase 2 dispatcher wiring:
//   - `handleInbound(.manifestUpdated)` applies the snapshot to the
//     engine's ManifestStore + clears the FlowCache (hot reload path).
//   - Verdict path: when no manifest is loaded, the engine answers
//     `.drop` for every flow (fail-closed invariant in action).
//   - Manifest hot-reload: a manifest_updated message arriving while
//     the engine has a different snapshot replaces the snapshot
//     atomically; the next evaluate(_:) consults the new rules.
//   - `notifyVerdict` builds the right IpcMessage for each outcome
//     class and calls the IPC client's `send`. Without a live UDS
//     transport the send fails with `.sendBeforeHandshake`; that
//     failure is captured via the dispatcher's sendErrorHandler so
//     the test can assert the builder produced a message at all.
//   - Decision-emit shape: round-trip through
//     `IPCBridgeNotifications.buildFlowDecisionRecorded` /
//     `buildFlowPendingApproval` (validated indirectly via the
//     dispatcher's wire emission).
//
// What this file does NOT cover:
//   - Live UDS transport / handshake round-trip. The IPCClient is
//     still at foundation scope; the dispatcher tests instantiate
//     the client but do not `start()` it, so `notifyVerdict` exercises
//     the pre-handshake guard path. Live IPC integration tests
//     land alongside the .systemextension install scope (Alpha-4).
//

import XCTest
import CryptoKit
@testable import CastleWallFilter
import CastleWallIPC

final class ExtensionDispatcherTests: XCTestCase {

    final class ImmediateAuditProducerSigner: AuditProducerSigning {
        let privateKey: Curve25519.Signing.PrivateKey

        init(privateKey: Curve25519.Signing.PrivateKey) {
            self.privateKey = privateKey
        }

        func signAuditProducerPayload(
            _ payload: Data,
            reply: @escaping (Data?, String?) -> Void
        ) {
            reply(try? privateKey.signature(for: payload), nil)
        }
    }

    // MARK: - Helpers

    func makeFlow(
        host: String? = "api.anthropic.com",
        ip: String = "104.18.32.10",
        port: Int = 443,
        agent: String = "agent-7",
        template: String = "coding-assistant"
    ) -> FilterFlowDescriptor {
        return FilterFlowDescriptor(
            sourceAppIdentifier: "ai.sanctuaryprotocol.test",
            agentId: agent,
            templateId: template,
            destinationHost: host,
            destinationIp: ip,
            destinationPort: port,
            networkProtocol: .tcp,
            hostnameSource: host != nil ? "sni" : nil,
            opaqueDestination: host == nil,
            // Attributed agent flow: these fixtures exercise the allowlist
            // allow-path, not the #905 unattributed fail-closed suppression.
            sourceUnattributed: false
        )
    }

    func makeRule(
        id: String,
        host: String,
        port: Int,
        disposition: String
    ) -> ManifestRule {
        return ManifestRule(
            id: id,
            schemaVersion: 1,
            createdAt: "2026-05-11T00:00:00Z",
            description: nil,
            match: ManifestRuleMatch(
                host: ManifestRuleHostMatch.single(host),
                hostPattern: nil,
                port: ManifestRulePortMatch.single(port),
                protocolName: nil
            ),
            scope: ManifestRuleScope(agentIds: nil, templateIds: nil),
            disposition: disposition,
            timeWindow: nil
        )
    }

    /// Build an IPC client that points at a non-existent UDS path. Tests
    /// drive `handleInbound` and `notifyVerdict` directly without
    /// starting the client; the path is never opened.
    func makeFloatingClient(pinnedPublicKey: Data = Data(repeating: 0, count: 32)) -> IPCClient {
        let opts = IPCClientOptions(
            path: "/tmp/castle-wall-test-no-such-socket.sock"
        )
        return IPCClient(
            options: opts,
            pinnedPublicKey: pinnedPublicKey
        )
    }

    // MARK: - Inbound: manifest_updated applies snapshot + clears cache

    func test_handleInbound_manifestUpdated_appliesToEngineStore() throws {
        let engine = FlowEvaluatorEngine()
        let rule = makeRule(id: "r-1", host: "api.anthropic.com", port: 443, disposition: "allow")
        let signed = try makeSignedManifestUpdatedBody(rules: [rule])
        let dispatcher = ExtensionDispatcher(
            engine: engine,
            ipcClient: makeFloatingClient(pinnedPublicKey: signed.publicKey)
        )

        XCTAssertFalse(engine.manifestStore.hasSnapshot)

        dispatcher.handleInbound(.manifestUpdated(signed.body))

        XCTAssertTrue(engine.manifestStore.hasSnapshot)
        XCTAssertEqual(engine.manifestStore.currentRules().count, 1)
        XCTAssertEqual(engine.manifestStore.currentRules().first?.id, "r-1")
    }

    func test_handleInbound_manifestUpdated_clearsFlowCacheOnReplace() throws {
        let engine = FlowEvaluatorEngine()
        let allowRule = makeRule(id: "r-allow", host: "api.anthropic.com", port: 443, disposition: "allow")
        let denyRule = makeRule(id: "r-deny", host: "api.anthropic.com", port: 443, disposition: "deny")
        let key = Curve25519.Signing.PrivateKey()
        let signedAllow = try makeSignedManifestUpdatedBody(rules: [allowRule], privateKey: key)
        let signedDeny = try makeSignedManifestUpdatedBody(rules: [denyRule], privateKey: key)
        let dispatcher = ExtensionDispatcher(
            engine: engine,
            ipcClient: makeFloatingClient(pinnedPublicKey: signedAllow.publicKey)
        )

        // Seed snapshot A and evaluate to populate the cache.
        dispatcher.handleInbound(.manifestUpdated(signedAllow.body))
        let flow = makeFlow()
        let outcomeA = engine.evaluate(flow)
        XCTAssertEqual(outcomeA, .allow(matchedRuleId: "r-allow"))
        XCTAssertEqual(engine.flowCache.count, 1)

        // Replace with snapshot B (deny). Cache MUST be cleared so the
        // next evaluate consults the new rules, not the cached allow.
        dispatcher.handleInbound(.manifestUpdated(signedDeny.body))
        XCTAssertEqual(engine.flowCache.count, 0, "cache must clear on manifest replace")
        let outcomeB = engine.evaluate(flow)
        XCTAssertEqual(outcomeB, .drop(matchedRuleId: "r-deny"))
    }

    // MARK: - Hot-reload latency invariant

    func test_handleInbound_manifestUpdated_hotReload_withinPerfCeiling() throws {
        // Build a manifest with 1000 rules to exercise a non-trivial
        // load. The reload itself typically completes in well under
        // 100ms on an unloaded machine, but this is a debug build run
        // via `swift test` on shared/loaded CI runners (and loaded dev
        // machines), where wall-clock timing carries real jitter that
        // has nothing to do with the algorithm's actual complexity.
        let rules: [ManifestRule] = (0..<1000).map { i in
            makeRule(
                id: "r-\(i)",
                host: "host-\(i).example.com",
                port: 443,
                disposition: "allow"
            )
        }

        // A single-shot wall-clock sample flakes under CI/dev-machine
        // load (GC/scheduler jitter, or a noisy-neighbor build sharing
        // the same machine): take the best of 3 fresh samples instead,
        // matching the retry:3 pattern used for other single-shot perf
        // assertions elsewhere (#790). The bound is widened from the
        // original 100ms to 600ms, which still leaves well over an
        // order of magnitude of headroom before it would catch an
        // actual quadratic regression on 1000 rules (which would push
        // into the seconds), while comfortably absorbing observed CI
        // jitter (drill evidence: raw single-shot CI failures up to
        // 222ms; best-of-3 samples up to ~500ms on a dev Mac under
        // heavy concurrent-build contention). A genuine regression
        // slows every sample; a one-off hiccup only slows one, so
        // best-of-3 plus the wider bound stays a real guard against
        // regressions, not a rubber stamp.
        var bestElapsedMs = Double.greatestFiniteMagnitude
        for _ in 0..<3 {
            let engine = FlowEvaluatorEngine()
            let signed = try makeSignedManifestUpdatedBody(rules: rules)
            let dispatcher = ExtensionDispatcher(
                engine: engine,
                ipcClient: makeFloatingClient(pinnedPublicKey: signed.publicKey)
            )

            let start = DispatchTime.now()
            dispatcher.handleInbound(.manifestUpdated(signed.body))
            let elapsedNs = DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds
            let elapsedMs = Double(elapsedNs) / 1_000_000.0

            // Correctness assertions stay hard on every sample; only the
            // timing bound below is judged against the best-of-3.
            XCTAssertTrue(engine.manifestStore.hasSnapshot)
            XCTAssertEqual(engine.manifestStore.currentRules().count, 1000)

            bestElapsedMs = min(bestElapsedMs, elapsedMs)
        }

        XCTAssertLessThan(bestElapsedMs, 600.0, "hot-reload best-of-3 took \(bestElapsedMs)ms; expected <600ms")
    }

    // MARK: - Fail-closed: no manifest loaded → engine answers .drop

    func test_failClosed_emptyManifest_answersDrop() {
        let engine = FlowEvaluatorEngine()
        // Deliberately do NOT call handleInbound; engine has no manifest.
        let flow = makeFlow()
        let outcome = engine.evaluate(flow)
        XCTAssertEqual(
            outcome,
            .drop(matchedRuleId: nil),
            "engine must default-deny when no manifest snapshot is loaded"
        )
    }

    func test_failClosed_emptyRulesSnapshot_answersDrop() throws {
        let engine = FlowEvaluatorEngine()
        let signed = try makeSignedManifestUpdatedBody(rules: [])
        let dispatcher = ExtensionDispatcher(
            engine: engine,
            ipcClient: makeFloatingClient(pinnedPublicKey: signed.publicKey)
        )
        // Apply an explicit EMPTY manifest. The engine still answers
        // .drop because no allow rule matches.
        dispatcher.handleInbound(.manifestUpdated(signed.body))
        let outcome = engine.evaluate(makeFlow())
        XCTAssertEqual(outcome, .drop(matchedRuleId: nil))
    }

    func test_bindingState_tracksManifestAndLeaseReceipt() throws {
        let engine = FlowEvaluatorEngine()
        let signed = try makeSignedManifestUpdatedBody(rules: [])
        let dispatcher = ExtensionDispatcher(
            engine: engine,
            ipcClient: makeFloatingClient(pinnedPublicKey: signed.publicKey)
        )

        XCTAssertFalse(dispatcher.bindingState.manifestReceived)
        XCTAssertFalse(dispatcher.bindingState.armLeaseReceived)

        dispatcher.handleInbound(.manifestUpdated(signed.body))
        XCTAssertTrue(dispatcher.bindingState.manifestReceived)
        XCTAssertFalse(dispatcher.bindingState.armLeaseReceived)

        dispatcher.handleInbound(.armLease(ArmLeaseBody(
            armed: true,
            ttlSeconds: nil,
            heartbeatIntervalSeconds: 5,
            updatedAt: "2026-06-11T00:00:00.000Z"
        )))
        XCTAssertTrue(dispatcher.bindingState.manifestReceived)
        XCTAssertTrue(dispatcher.bindingState.armLeaseReceived)
    }

    func test_rejectedManifest_doesNotMarkManifestReceived() throws {
        // S5-0 HIGH-2 observability (b): a REJECTED manifest (verifier throw ->
        // applyManifestUpdated returns nil, prior policy kept) must NOT advance
        // manifestReceived. Otherwise isProviderBound would report bound on the
        // strength of a policy push that never applied.
        let engine = FlowEvaluatorEngine()
        // A validly-signed body whose raw rule scope is off-spec (uids:null):
        // it verifies signature+digest but fails the schema chokepoint.
        let bad = try makeSignedBodyWithRawRules(
            rawRuleJSONs: [
                #"{"id":"gate-scoped","schema_version":1,"created_at":"2026-07-14T00:00:00Z","match":{"host":["gate-endpoint.example.com"],"port":[443],"protocol":"tcp"},"scope":{"uids":null},"disposition":"allow"}"#
            ],
            agentOrigin: AgentOriginWire(mode: .uid, agentUid: 600, gateUid: 601, systemUidAllowCeiling: 500)
        )
        let dispatcher = ExtensionDispatcher(
            engine: engine,
            ipcClient: makeFloatingClient(pinnedPublicKey: bad.publicKey)
        )

        XCTAssertFalse(dispatcher.bindingState.manifestReceived)
        dispatcher.handleInbound(.manifestUpdated(bad.body))
        XCTAssertFalse(
            dispatcher.bindingState.manifestReceived,
            "a rejected manifest must not mark manifest_received"
        )
        XCTAssertFalse(engine.manifestStore.hasSnapshot, "rejected rules never went live")

        // Control: a subsequent WELL-FORMED manifest still applies and advances
        // the flag (the rejection is not sticky / not a policy-refresh DoS).
        let good = try makeSignedManifestUpdatedBody(
            rules: [makeRule(id: "r-ok", host: "api.anthropic.com", port: 443, disposition: "allow")],
            privateKey: Curve25519.Signing.PrivateKey()
        )
        let dispatcher2 = ExtensionDispatcher(
            engine: engine,
            ipcClient: makeFloatingClient(pinnedPublicKey: good.publicKey)
        )
        dispatcher2.handleInbound(.manifestUpdated(good.body))
        XCTAssertTrue(dispatcher2.bindingState.manifestReceived)
        XCTAssertTrue(engine.manifestStore.hasSnapshot)
    }

    func test_buildProviderUnboundAudit_usesAcceptedEventShape() {
        let message = ExtensionDispatcher.buildProviderUnboundAudit(
            fortressId: "fortress-test",
            trigger: "verdict",
            manifestReceived: false,
            armLeaseReceived: false,
            timestamp: "2026-06-11T00:00:00.000Z"
        )

        guard case .auditEmit(let event) = message else {
            return XCTFail("expected audit_emit")
        }
        guard case .object(let object) = event else {
            return XCTFail("expected audit object")
        }
        XCTAssertEqual(object["event_type"], .string("provider_unbound"))
        XCTAssertEqual(object["fortress_id"], .string("fortress-test"))
        guard case .object(let details)? = object["details"] else {
            return XCTFail("expected details object")
        }
        XCTAssertEqual(details["source"], .string("macos_extension"))
        XCTAssertEqual(details["trigger"], .string("verdict"))
        XCTAssertEqual(details["manifest_received"], .bool(false))
        XCTAssertEqual(details["arm_lease_received"], .bool(false))
    }

    // MARK: - Outbound: notifyVerdict drops while disconnected

    func test_notifyVerdict_allow_dropsWhileDisconnected() {
        let engine = FlowEvaluatorEngine()
        let sendError = self.expectation(description: "send error not fired")
        sendError.isInverted = true
        let handler: ExtensionDispatcher.SendErrorHandler = { _ in
            sendError.fulfill()
        }
        let dispatcher = ExtensionDispatcher(
            engine: engine,
            ipcClient: makeFloatingClient(),
            sendErrorHandler: handler
        )
        dispatcher.notifyVerdict(.allow(matchedRuleId: "r-1"), for: makeFlow())
        wait(for: [sendError], timeout: 0.1)
        XCTAssertEqual(dispatcher.connectionState, .disconnected)
    }

    func test_notifyVerdict_drop_dropsWhileDisconnected() {
        let engine = FlowEvaluatorEngine()
        let sendError = self.expectation(description: "send error not fired")
        sendError.isInverted = true
        let dispatcher = ExtensionDispatcher(
            engine: engine,
            ipcClient: makeFloatingClient(),
            sendErrorHandler: { _ in
                sendError.fulfill()
            }
        )
        dispatcher.notifyVerdict(.drop(matchedRuleId: "r-2"), for: makeFlow())
        wait(for: [sendError], timeout: 0.1)
        XCTAssertEqual(dispatcher.connectionState, .disconnected)
    }

    func test_notifyVerdict_uncertain_dropsWhileDisconnected() {
        let engine = FlowEvaluatorEngine()
        let sendError = self.expectation(description: "send error not fired")
        sendError.isInverted = true
        let dispatcher = ExtensionDispatcher(
            engine: engine,
            ipcClient: makeFloatingClient(),
            sendErrorHandler: { _ in
                sendError.fulfill()
            }
        )
        dispatcher.notifyVerdict(.uncertain, for: makeFlow())
        wait(for: [sendError], timeout: 0.1)
        XCTAssertEqual(dispatcher.connectionState, .disconnected)
    }

    /// Slice-M audit-drop fix: a verdict on a NEVER-STARTED dispatcher must
    /// NOT kick a connection attempt. The lazy-rebind path is gated on
    /// `hasEverStarted`, so the pristine `.disconnected` state is preserved
    /// and a not-yet-bootstrapped provider does not race its own bootstrap.
    /// Several verdicts in a row stay `.disconnected` (no transition to
    /// `.handshaking` / `.retrying`).
    func test_notifyVerdict_neverStarted_doesNotLazyReconnect() {
        let engine = FlowEvaluatorEngine()
        let dispatcher = ExtensionDispatcher(
            engine: engine,
            ipcClient: makeFloatingClient(),
            sendErrorHandler: { _ in }
        )
        for _ in 0..<5 {
            dispatcher.notifyVerdict(.allow(matchedRuleId: "r-1"), for: makeFlow())
        }
        // Give any errant async reconnect a chance to flip the state.
        let settle = self.expectation(description: "settle")
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.1) { settle.fulfill() }
        wait(for: [settle], timeout: 1.0)
        XCTAssertEqual(
            dispatcher.connectionState,
            .disconnected,
            "a never-started dispatcher must not lazy-reconnect from notifyVerdict"
        )
    }

    /// Slice-M LAYER-1 starvation regression (`612f8d99`). Once `start()` has
    /// failed its connect and scheduled a retry, the dispatcher sits in
    /// `.retrying` with a PENDING retry timer. Steady verdict traffic — which an
    /// armed wall produces constantly — must NOT keep resetting that timer, or
    /// `attemptStartAndSubscribe` never fires and the audit channel never
    /// reconnects (the 2026-06-29 drill: 0 producer-signed entries, endless
    /// "reconnect scheduled" spam, zero "connected"). The fix guards the
    /// reconnect-kick on `retryTimer == nil`; this test drives the exact
    /// condition and asserts the pending timer is left intact (no new
    /// reconnect scheduled) while verdicts pour in.
    func test_notifyVerdict_whileRetryPending_doesNotResetTimer_starvationRegression() async {
        let engine = FlowEvaluatorEngine()
        let dispatcher = ExtensionDispatcher(
            engine: engine,
            // Non-existent UDS path: the connect fails, so start() lands the
            // dispatcher in `.retrying` with a pending retry timer.
            ipcClient: makeFloatingClient(),
            sendErrorHandler: { _ in }
        )

        let live = await dispatcher.start()
        XCTAssertFalse(live, "start() against a dead socket must not report live")
        // The sync read drains the (serial) state queue, so the scheduleReconnect
        // dispatched by the start failure has fully run by the time we read.
        XCTAssertEqual(dispatcher.connectionState, .retrying)
        let baseline = dispatcher.reconnectScheduledCount
        XCTAssertEqual(baseline, 1, "a single failed start schedules exactly one reconnect")

        // Pour verdicts at the dispatcher while the retry timer is pending. The
        // PRE-fix livelock reset the timer on every one of these; the guard must
        // leave the pending timer untouched, so the schedule count stays put.
        for _ in 0..<100 {
            dispatcher.notifyVerdict(.allow(matchedRuleId: "r-1"), for: makeFlow())
        }
        // Settle async drop bookkeeping, staying well under the ~0.85s minimum
        // retry delay so the pending timer cannot legitimately fire mid-window.
        try? await Task.sleep(nanoseconds: 150_000_000)

        XCTAssertEqual(
            dispatcher.reconnectScheduledCount,
            baseline,
            "verdicts while a retry timer is pending must NOT reschedule (starvation guard)"
        )
        XCTAssertEqual(
            dispatcher.connectionState,
            .retrying,
            "the dispatcher must remain in .retrying with its original pending timer"
        )
        dispatcher.stop()
    }

    // MARK: - Outbound message-shape correctness via the builder

    func test_decisionRecordedShape_allow_carriesMatchedRuleId() {
        let flow = makeFlow()
        let message = IPCBridgeNotifications.buildFlowDecisionRecorded(
            outcome: .allow(matchedRuleId: "r-allow"),
            flow: flow
        )
        guard case .flowDecisionRecorded(let body) = message else {
            XCTFail("expected flowDecisionRecorded; got \(String(describing: message))")
            return
        }
        XCTAssertEqual(body.decision, "allow")
        XCTAssertEqual(body.matchedRuleId, "r-allow")
        XCTAssertEqual(body.agent.id, flow.agentId)
        XCTAssertEqual(body.destination.host, flow.destinationHost)
    }

    func test_decisionRecordedShape_drop_carriesMatchedRuleIdAndNullForDefaultDeny() {
        let flow = makeFlow()
        let withRule = IPCBridgeNotifications.buildFlowDecisionRecorded(
            outcome: .drop(matchedRuleId: "r-deny"),
            flow: flow
        )
        guard case .flowDecisionRecorded(let body) = withRule else {
            XCTFail("expected flowDecisionRecorded")
            return
        }
        XCTAssertEqual(body.decision, "drop")
        XCTAssertEqual(body.matchedRuleId, "r-deny")

        let defaultDeny = IPCBridgeNotifications.buildFlowDecisionRecorded(
            outcome: .drop(matchedRuleId: nil),
            flow: flow
        )
        guard case .flowDecisionRecorded(let body2) = defaultDeny else {
            XCTFail("expected flowDecisionRecorded")
            return
        }
        XCTAssertEqual(body2.decision, "drop")
        XCTAssertNil(body2.matchedRuleId)
    }

    func test_decisionRecordedShape_uncertain_returnsNil() {
        // Uncertain outcomes route through flow_pending_approval, NOT
        // flow_decision_recorded. The builder returns nil for the
        // decision-recorded path so the dispatcher never sends a
        // decision message with no recorded decision.
        let flow = makeFlow()
        let message = IPCBridgeNotifications.buildFlowDecisionRecorded(
            outcome: .uncertain,
            flow: flow
        )
        XCTAssertNil(message)
    }

    func test_pendingApprovalShape_buildsRequestIdAndEgressSurface() {
        let flow = makeFlow()
        let message = IPCBridgeNotifications.buildFlowPendingApproval(
            flow: flow,
            requestId: "fixed-req-id",
            expiresInSeconds: 45
        )
        guard case .flowPendingApproval(let body) = message else {
            XCTFail("expected flowPendingApproval")
            return
        }
        XCTAssertEqual(body.requestId, "fixed-req-id")
        XCTAssertEqual(body.surface, "egress")
        XCTAssertEqual(body.expiresInSeconds, 45)
        XCTAssertEqual(body.agent.id, flow.agentId)
        XCTAssertEqual(body.destination.host, flow.destinationHost)
    }

    func test_auditProducerChain_signsAllowVerdictWithDomainSeparatedBytes() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let signer = ImmediateAuditProducerSigner(privateKey: privateKey)
        let chain = AuditProducerChain()
        let flow = makeFlow()
        let recordedAt = Date(timeIntervalSince1970: 1_760_000_000)
        let exp = expectation(description: "signed verdict")
        var signedMessage: IpcMessage?
        var signedError: AuditProducerSigningError?

        chain.buildSignedFlowDecision(
            outcome: .allow(matchedRuleId: "r-allow"),
            flow: flow,
            recordedAt: recordedAt,
            signer: signer
        ) { result in
            switch result {
            case .success(let message):
                signedMessage = message
            case .failure(let error):
                signedError = error
            }
            exp.fulfill()
        }
        wait(for: [exp], timeout: 1)

        XCTAssertNil(signedError)
        guard case .flowDecisionRecorded(let body)? = signedMessage else {
            return XCTFail("expected signed flowDecisionRecorded")
        }
        let producer = try XCTUnwrap(body.producer)
        XCTAssertEqual(producer.seq, 0)
        XCTAssertNil(producer.priorSha256Hex)
        XCTAssertEqual(producer.keyId, AuditProducerSigningConstants.keyId)
        let signature = try Base64URL.decode(producer.signatureB64url)
        let payload = Data(
            "\(AuditProducerSigningConstants.domainPrefix)\(producer.eventCanonicalJson)\n\(producer.capturedAtUnixMs)\n\(producer.seq)".utf8
        )
        XCTAssertTrue(
            privateKey.publicKey.isValidSignature(signature, for: payload),
            "signature must verify over the exact domain-separated producer bytes"
        )
    }
}
