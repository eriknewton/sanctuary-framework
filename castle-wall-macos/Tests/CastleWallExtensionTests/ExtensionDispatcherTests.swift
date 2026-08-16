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

    /// Drill Leg 3 (2026-07-15) repro: an XPC signer whose reply block is
    /// DROPPED (never invoked) and whose error handler also never fires, the
    /// exact silent-stall the drill observed. The chain's watchdog must convert
    /// this into a loud failure rather than hang forever with no drop line.
    final class NeverRepliesAuditProducerSigner: AuditProducerSigning {
        func signAuditProducerPayload(
            _ payload: Data,
            reply: @escaping (Data?, String?) -> Void
        ) {
            // Intentionally never calls `reply` (nor an error): the dropped-reply
            // condition that stranded emission.
        }
    }

    /// A signer that replies LATE (after `delay`), to prove a reply arriving
    /// after the watchdog already fired is a harmless no-op (never double-fires,
    /// never advances the chain for a flow already reported as dropped).
    final class DelayedAuditProducerSigner: AuditProducerSigning {
        let privateKey: Curve25519.Signing.PrivateKey
        let delay: TimeInterval

        init(privateKey: Curve25519.Signing.PrivateKey, delay: TimeInterval) {
            self.privateKey = privateKey
            self.delay = delay
        }

        func signAuditProducerPayload(
            _ payload: Data,
            reply: @escaping (Data?, String?) -> Void
        ) {
            let key = privateKey
            DispatchQueue.global().asyncAfter(deadline: .now() + delay) {
                reply(try? key.signature(for: payload), nil)
            }
        }
    }

    final class HoldingAuditProducerSigner: AuditProducerSigning {
        let privateKey: Curve25519.Signing.PrivateKey
        private let lock = NSLock()
        private var storedReplies: [() -> Void] = []
        var replies: [() -> Void] {
            lock.lock()
            defer { lock.unlock() }
            return storedReplies
        }

        init(privateKey: Curve25519.Signing.PrivateKey) {
            self.privateKey = privateKey
        }

        func signAuditProducerPayload(
            _ payload: Data,
            reply: @escaping (Data?, String?) -> Void
        ) {
            let key = privateKey
            lock.lock()
            storedReplies.append {
                reply(try? key.signature(for: payload), nil)
            }
            lock.unlock()
        }

        func resolve(_ index: Int) {
            let reply = replies[index]
            reply()
        }
    }

    enum StateStoreError: Error {
        case refused
    }

    final class FailingAuditProducerStateStore: AuditProducerChainStateStore {
        func load() throws -> AuditProducerChainState? {
            return nil
        }

        func save(_ state: AuditProducerChainState) throws {
            throw StateStoreError.refused
        }
    }

    func volatileStateStore() -> AuditProducerChainStateStore {
        return VolatileAuditProducerChainStateStore()
    }

    func hashSignedBody(_ canonicalJson: String) -> String {
        let digest = SHA256.hash(data: Data(canonicalJson.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    func makeFlow(
        host: String? = "api.anthropic.com",
        ip: String = "104.18.32.10",
        port: Int = 443,
        agent: String = "agent-7",
        template: String = "coding-assistant",
        sourceRuid: uid_t = 0
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
            sourceRuid: sourceRuid,
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

    /// Arm the dispatcher with a lease signed by `key` (which must be the
    /// private half of the dispatcher's pinned public key) and a fresh stamp —
    /// O-02: an unsigned or stale lease is rejected at `handleInbound`.
    func arm(_ dispatcher: ExtensionDispatcher, key: Curve25519.Signing.PrivateKey) {
        let body = try! makeSignedArmLeaseBody(
            updatedAt: isoLeaseStamp(Date()),
            privateKey: key
        )
        dispatcher.handleInbound(.armLease(body))
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
        arm(dispatcher, key: key)

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

    func test_manifestPresentWithoutArmLease_forcesAgentAllowClosed() throws {
        let engine = FlowEvaluatorEngine()
        let allowRule = makeRule(id: "r-agent-allow", host: "api.anthropic.com", port: 443, disposition: "allow")
        let signed = try makeSignedManifestUpdatedBody(
            rules: [allowRule],
            agentOrigin: AgentOriginWire(mode: .uid, agentUid: 600, systemUidAllowCeiling: 500)
        )
        let dispatcher = ExtensionDispatcher(
            engine: engine,
            ipcClient: makeFloatingClient(pinnedPublicKey: signed.publicKey)
        )

        dispatcher.handleInbound(.manifestUpdated(signed.body))

        XCTAssertTrue(dispatcher.bindingState.manifestReceived)
        XCTAssertFalse(dispatcher.bindingState.armLeaseReceived)
        XCTAssertEqual(engine.armLease.missingLeaseReason(), "arm_lease_missing")
        XCTAssertEqual(
            engine.evaluate(makeFlow(sourceRuid: 600)),
            .drop(matchedRuleId: ArmLease.missingLeaseRuleId),
            "a real signed manifest must not allow an agent flow until an arm lease has arrived"
        )
    }

    // MARK: - Hot-reload latency invariant

    func test_handleInbound_manifestUpdated_hotReload_withinPerfCeiling() throws {
        func makeRules(_ count: Int) -> [ManifestRule] {
            return (0..<count).map { i in
                makeRule(
                    id: "r-\(i)",
                    host: "host-\(i).example.com",
                    port: 443,
                    disposition: "allow"
                )
            }
        }

        func bestHotReloadElapsedMs(ruleCount: Int, samples: Int = 3) throws -> Double {
            let rules = makeRules(ruleCount)
            var bestElapsedMs = Double.greatestFiniteMagnitude
            for _ in 0..<samples {
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
                XCTAssertEqual(engine.manifestStore.currentRules().count, ruleCount)

                bestElapsedMs = min(bestElapsedMs, elapsedMs)
            }
            return bestElapsedMs
        }

        // A fixed wall-clock ceiling flakes under CI/dev-machine load because
        // scheduler stalls slow an otherwise-linear reload. Keep a real perf
        // guard by comparing the 1000-rule reload against a smaller same-process
        // reload, while allowing a loaded-run floor that absorbs host jitter.
        let smallElapsedMs = try bestHotReloadElapsedMs(ruleCount: 250)
        let largeElapsedMs = try bestHotReloadElapsedMs(ruleCount: 1000)
        let dynamicCeilingMs = max(1_500.0, smallElapsedMs * 12.0 + 250.0)

        XCTAssertLessThan(
            largeElapsedMs,
            dynamicCeilingMs,
            "hot-reload best-of-3 took \(largeElapsedMs)ms for 1000 rules; expected <\(dynamicCeilingMs)ms based on 250-rule baseline \(smallElapsedMs)ms"
        )
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
        let key = Curve25519.Signing.PrivateKey()
        let signed = try makeSignedManifestUpdatedBody(rules: [], privateKey: key)
        let dispatcher = ExtensionDispatcher(
            engine: engine,
            ipcClient: makeFloatingClient(pinnedPublicKey: signed.publicKey)
        )

        XCTAssertFalse(dispatcher.bindingState.manifestReceived)
        XCTAssertFalse(dispatcher.bindingState.armLeaseReceived)

        dispatcher.handleInbound(.manifestUpdated(signed.body))
        XCTAssertTrue(dispatcher.bindingState.manifestReceived)
        XCTAssertFalse(dispatcher.bindingState.armLeaseReceived)

        dispatcher.handleInbound(.armLease(try makeSignedArmLeaseBody(
            updatedAt: isoLeaseStamp(Date()),
            privateKey: key
        )))
        XCTAssertTrue(dispatcher.bindingState.manifestReceived)
        XCTAssertTrue(dispatcher.bindingState.armLeaseReceived)
    }

    // MARK: - O-02: arm-lease trust boundary at the dispatcher

    func test_unsignedArmLease_rejected_doesNotBindOrUpdateEngine() throws {
        let engine = FlowEvaluatorEngine()
        let key = Curve25519.Signing.PrivateKey()
        let dispatcher = ExtensionDispatcher(
            engine: engine,
            ipcClient: makeFloatingClient(pinnedPublicKey: key.publicKey.rawRepresentation)
        )

        dispatcher.handleInbound(.armLease(ArmLeaseBody(
            armed: true,
            ttlSeconds: nil,
            heartbeatIntervalSeconds: 5,
            updatedAt: isoLeaseStamp(Date())
        )))

        // MUST-NEVER #5: the unsigned frame is REJECTED — never accepted with
        // a warning. Neither the binding flag nor the engine lease may move.
        XCTAssertFalse(dispatcher.bindingState.armLeaseReceived)
        XCTAssertNotNil(engine.armLease.missingLeaseReason())
    }

    func test_wrongKeyArmLease_rejected() throws {
        let engine = FlowEvaluatorEngine()
        let pinnedKey = Curve25519.Signing.PrivateKey()
        let dispatcher = ExtensionDispatcher(
            engine: engine,
            ipcClient: makeFloatingClient(pinnedPublicKey: pinnedKey.publicKey.rawRepresentation)
        )

        dispatcher.handleInbound(.armLease(try makeSignedArmLeaseBody(
            updatedAt: isoLeaseStamp(Date()),
            privateKey: Curve25519.Signing.PrivateKey()
        )))

        XCTAssertFalse(dispatcher.bindingState.armLeaseReceived)
        XCTAssertNotNil(engine.armLease.missingLeaseReason())
    }

    func test_replayedArmLease_rejected_doesNotExtendDeadManDeadline() throws {
        // The O-02 replay scenario proper: the lease deadline anchors to the
        // EXTENSION clock at acceptance, so replaying a captured frame would
        // extend `heartbeatExpiresAt` forever if `updated_at` were not
        // consumed. With the monotonic gate, the replay is rejected and the
        // deadline stays anchored to the FIRST acceptance.
        var engineNow = Date()
        let lease = ArmLease(now: { engineNow })
        let engine = FlowEvaluatorEngine(armLease: lease)
        let key = Curve25519.Signing.PrivateKey()
        let dispatcher = ExtensionDispatcher(
            engine: engine,
            ipcClient: makeFloatingClient(pinnedPublicKey: key.publicKey.rawRepresentation)
        )

        let frame = try makeSignedArmLeaseBody(
            updatedAt: isoLeaseStamp(Date()),
            privateKey: key
        )
        dispatcher.handleInbound(.armLease(frame))
        XCTAssertTrue(dispatcher.bindingState.armLeaseReceived)
        let deadlineAfterFirst = engine.armLease.snapshot().heartbeatExpiresAt

        // Time passes; the captured frame is replayed verbatim.
        engineNow = engineNow.addingTimeInterval(6)
        dispatcher.handleInbound(.armLease(frame))

        XCTAssertEqual(
            engine.armLease.snapshot().heartbeatExpiresAt,
            deadlineAfterFirst,
            "a replayed lease must not re-anchor the dead-man deadline"
        )
    }

    func test_olderStampArmLease_rejected_cannotRollBackArmState() throws {
        let engine = FlowEvaluatorEngine()
        let key = Curve25519.Signing.PrivateKey()
        let dispatcher = ExtensionDispatcher(
            engine: engine,
            ipcClient: makeFloatingClient(pinnedPublicKey: key.publicKey.rawRepresentation)
        )

        let armedNow = try makeSignedArmLeaseBody(
            armed: true,
            updatedAt: isoLeaseStamp(Date()),
            privateKey: key
        )
        dispatcher.handleInbound(.armLease(armedNow))
        XCTAssertTrue(engine.armLease.snapshot().armed)

        // A validly-signed but OLDER disarm frame (e.g. captured from an
        // earlier disarm) must not roll the wall back.
        let staleDisarm = try makeSignedArmLeaseBody(
            armed: false,
            updatedAt: isoLeaseStamp(Date().addingTimeInterval(-30)),
            privateKey: key
        )
        dispatcher.handleInbound(.armLease(staleDisarm))

        XCTAssertTrue(
            engine.armLease.snapshot().armed,
            "an older-stamped lease must not overwrite newer arm state"
        )
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
        let chain = AuditProducerChain(stateStore: volatileStateStore())
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

    // Drill Leg 3 (2026-07-15): per-flow audit emission stopped SILENTLY because
    // the XPC sign reply was dropped and neither the reply nor the error handler
    // fired, so `buildSignedFlowDecision`'s completion never ran -> no emit, no
    // drop line. The watchdog MUST convert that stall into a loud failure so the
    // flow surfaces on the existing `path=signing-failure` drop probe instead of
    // vanishing (AGENTS.md rule 5).
    func test_auditProducerChain_droppedReply_firesLoudTimeoutFailure() {
        let signer = NeverRepliesAuditProducerSigner()
        let chain = AuditProducerChain(signTimeoutSeconds: 0.15, stateStore: volatileStateStore())
        let exp = expectation(description: "timeout failure")
        var result: Result<IpcMessage, AuditProducerSigningError>?

        chain.buildSignedFlowDecision(
            outcome: .allow(matchedRuleId: "r-allow"),
            flow: makeFlow(),
            signer: signer
        ) { r in
            result = r
            exp.fulfill()
        }
        // The completion must fire (loudly), not hang forever.
        wait(for: [exp], timeout: 2)

        guard case .failure(let error)? = result else {
            return XCTFail("dropped reply must surface as a failure, not silence")
        }
        // A signer-unavailable failure routes to the dispatcher's DROP-PATH 3,
        // which logs `[slice-m-audit-drop] path=signing-failure`.
        guard case .signerUnavailable(let detail) = error else {
            return XCTFail("expected signerUnavailable, got \(error)")
        }
        XCTAssertTrue(
            detail.contains("did not arrive"),
            "timeout failure should name the dropped/timed-out reply; got: \(detail)"
        )
    }

    func test_auditProducerChain_completionFiresExactlyOnce_onTimeoutThenLateReply() {
        // A reply that arrives AFTER the watchdog already fired must be a no-op:
        // never a second completion, and never advance the chain for a flow
        // already reported dropped.
        let privateKey = Curve25519.Signing.PrivateKey()
        let stateURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("audit-producer-timeout-\(UUID().uuidString)")
            .appendingPathComponent("state.json")
        defer { try? FileManager.default.removeItem(at: stateURL.deletingLastPathComponent()) }
        let store = FileAuditProducerChainStateStore(url: stateURL)
        let chain = AuditProducerChain(signTimeoutSeconds: 0.1, stateStore: store)

        let firstExp = expectation(description: "first completion (timeout)")
        var completionCount = 0
        var firstResultIsFailure = false
        chain.buildSignedFlowDecision(
            outcome: .allow(matchedRuleId: "r-allow"),
            flow: makeFlow(),
            signer: DelayedAuditProducerSigner(privateKey: privateKey, delay: 0.4)
        ) { r in
            completionCount += 1
            if case .failure = r { firstResultIsFailure = true }
            firstExp.fulfill()
        }
        wait(for: [firstExp], timeout: 2)
        XCTAssertTrue(firstResultIsFailure, "the timeout must win over the late reply")

        // Give the late reply (0.4s) time to arrive and be discarded.
        Thread.sleep(forTimeInterval: 0.6)
        XCTAssertEqual(completionCount, 1, "the late reply must not fire a second completion")

        // The persistent cursor must remain unadvanced across a restart;
        // otherwise a timeout would hide a flow by saving past an unsent event.
        let restartExp = expectation(description: "restart after timeout keeps seq 0")
        var restartSeq: UInt64?
        AuditProducerChain(stateStore: store).buildSignedFlowDecision(
            outcome: .allow(matchedRuleId: "r-allow"),
            flow: makeFlow(),
            signer: ImmediateAuditProducerSigner(privateKey: privateKey)
        ) { r in
            if case .success(.flowDecisionRecorded(let body)) = r {
                restartSeq = body.producer?.seq
            }
            restartExp.fulfill()
        }
        wait(for: [restartExp], timeout: 2)
        XCTAssertEqual(
            restartSeq,
            0,
            "a dropped/timed-out flow must not advance the durable cursor"
        )
    }

    func test_auditProducerChain_successAdvancesSeqAcrossFlows() {
        // The happy path still advances the chain: two sequential signed flows
        // get seq 0 then seq 1 (the one-shot guard advances on the winning
        // success, unchanged behavior).
        let privateKey = Curve25519.Signing.PrivateKey()
        let signer = ImmediateAuditProducerSigner(privateKey: privateKey)
        let chain = AuditProducerChain(stateStore: volatileStateStore())

        func signSeq(_ label: String) -> UInt64? {
            let exp = expectation(description: label)
            var seq: UInt64?
            chain.buildSignedFlowDecision(
                outcome: .allow(matchedRuleId: "r-allow"),
                flow: makeFlow(),
                signer: signer
            ) { r in
                if case .success(.flowDecisionRecorded(let body)) = r {
                    seq = body.producer?.seq
                }
                exp.fulfill()
            }
            wait(for: [exp], timeout: 2)
            return seq
        }

        XCTAssertEqual(signSeq("first"), 0)
        XCTAssertEqual(signSeq("second"), 1)
    }

    func test_auditProducerChain_persistsSeqAcrossChainInstances() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let signer = ImmediateAuditProducerSigner(privateKey: privateKey)
        let stateURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("audit-producer-chain-\(UUID().uuidString)")
            .appendingPathComponent("state.json")
        defer { try? FileManager.default.removeItem(at: stateURL.deletingLastPathComponent()) }
        let store = FileAuditProducerChainStateStore(url: stateURL)

        func hashSignedBody(_ canonicalJson: String) -> String {
            let digest = SHA256.hash(data: Data(canonicalJson.utf8))
            return digest.map { String(format: "%02x", $0) }.joined()
        }

        func signFlow(_ chain: AuditProducerChain, label: String) throws -> AuditProducerSignatureBody {
            let exp = expectation(description: label)
            var result: Result<IpcMessage, AuditProducerSigningError>?
            chain.buildSignedFlowDecision(
                outcome: .allow(matchedRuleId: "r-allow"),
                flow: makeFlow(),
                signer: signer
            ) { r in
                result = r
                exp.fulfill()
            }
            wait(for: [exp], timeout: 2)
            let message = try XCTUnwrap(result).get()
            guard case .flowDecisionRecorded(let body) = message else {
                XCTFail("expected signed flowDecisionRecorded")
                throw NSError(domain: "ExtensionDispatcherTests", code: 3)
            }
            return try XCTUnwrap(body.producer)
        }

        let first = try signFlow(
            AuditProducerChain(stateStore: store),
            label: "first chain instance"
        )
        let afterRestart = try signFlow(
            AuditProducerChain(stateStore: store),
            label: "second chain instance"
        )

        XCTAssertEqual(first.seq, 0)
        XCTAssertNil(first.priorSha256Hex)
        XCTAssertEqual(afterRestart.seq, 1)
        XCTAssertEqual(afterRestart.priorSha256Hex, hashSignedBody(first.eventCanonicalJson))
    }

    func test_auditProducerChain_adoptsHigherDurableRepairBeforeSigning() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let signer = ImmediateAuditProducerSigner(privateKey: privateKey)
        let stateURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("audit-producer-repair-\(UUID().uuidString)")
            .appendingPathComponent("state.json")
        defer { try? FileManager.default.removeItem(at: stateURL.deletingLastPathComponent()) }
        let store = FileAuditProducerChainStateStore(url: stateURL)
        let lowHash = String(repeating: "a", count: 64)
        let repairedHash = String(repeating: "b", count: 64)
        try store.save(AuditProducerChainState(nextSeq: 576, priorSha256Hex: lowHash))
        let chain = AuditProducerChain(stateStore: store)

        try store.save(AuditProducerChainState(nextSeq: 28_174, priorSha256Hex: repairedHash))

        let exp = expectation(description: "repaired cursor adopted")
        var producer: AuditProducerSignatureBody?
        chain.buildSignedFlowDecision(
            outcome: .allow(matchedRuleId: "r-allow"),
            flow: makeFlow(),
            signer: signer
        ) { result in
            if case .success(.flowDecisionRecorded(let body)) = result {
                producer = body.producer
            }
            exp.fulfill()
        }
        wait(for: [exp], timeout: 2)

        XCTAssertEqual(producer?.seq, 28_174)
        XCTAssertEqual(producer?.priorSha256Hex, repairedHash)
    }

    func test_auditProducerChain_doesNotOverwriteHigherDurableRepairWithLateLowReply() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let stateURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("audit-producer-late-low-\(UUID().uuidString)")
            .appendingPathComponent("state.json")
        defer { try? FileManager.default.removeItem(at: stateURL.deletingLastPathComponent()) }
        let store = FileAuditProducerChainStateStore(url: stateURL)
        let repairedHash = String(repeating: "c", count: 64)
        let chain = AuditProducerChain(stateStore: store)

        let exp = expectation(description: "late low reply rejected")
        var result: Result<IpcMessage, AuditProducerSigningError>?
        chain.buildSignedFlowDecision(
            outcome: .allow(matchedRuleId: "r-allow"),
            flow: makeFlow(),
            signer: DelayedAuditProducerSigner(privateKey: privateKey, delay: 0.2)
        ) { r in
            result = r
            exp.fulfill()
        }

        try store.save(AuditProducerChainState(nextSeq: 28_174, priorSha256Hex: repairedHash))
        wait(for: [exp], timeout: 2)

        guard case .failure(let error)? = result else {
            return XCTFail("the stale low-seq sign reply must be dropped")
        }
        XCTAssertEqual(error, .chainAdvancedBeforeSignReply)
        let persisted = try XCTUnwrap(store.load())
        XCTAssertEqual(persisted.nextSeq, 28_174)
        XCTAssertEqual(persisted.priorSha256Hex, repairedHash)
    }

    func test_auditProducerChain_unavailableDefaultStoreFailsClosed() {
        let privateKey = Curve25519.Signing.PrivateKey()
        let signer = ImmediateAuditProducerSigner(privateKey: privateKey)
        let chain = AuditProducerChain(
            stateStore: UnavailableAuditProducerChainStateStore(
                reason: "simulated missing application support directory"
            )
        )
        let exp = expectation(description: "unavailable store")
        var result: Result<IpcMessage, AuditProducerSigningError>?

        chain.buildSignedFlowDecision(
            outcome: .allow(matchedRuleId: "r-allow"),
            flow: makeFlow(),
            signer: signer
        ) { r in
            result = r
            exp.fulfill()
        }
        wait(for: [exp], timeout: 2)

        guard case .failure(let error)? = result else {
            return XCTFail("unavailable durable store must fail closed")
        }
        guard case .statePersistenceFailed(let detail) = error else {
            return XCTFail("expected statePersistenceFailed, got \(error)")
        }
        XCTAssertTrue(detail.contains("could not be loaded"))
    }

    func test_auditProducerChain_saveFailureDropsSignedEvent() {
        let privateKey = Curve25519.Signing.PrivateKey()
        let signer = ImmediateAuditProducerSigner(privateKey: privateKey)
        let chain = AuditProducerChain(stateStore: FailingAuditProducerStateStore())
        let exp = expectation(description: "state save failure")
        var result: Result<IpcMessage, AuditProducerSigningError>?

        chain.buildSignedFlowDecision(
            outcome: .allow(matchedRuleId: "r-allow"),
            flow: makeFlow(),
            signer: signer
        ) { r in
            result = r
            exp.fulfill()
        }
        wait(for: [exp], timeout: 2)

        guard case .failure(let error)? = result else {
            return XCTFail("state persistence failure must drop the signed event")
        }
        guard case .statePersistenceFailed(let detail) = error else {
            return XCTFail("expected statePersistenceFailed, got \(error)")
        }
        XCTAssertTrue(detail.contains("could not be saved"))
    }

    func test_auditProducerChain_serializesOverlappingFlowAndAvailabilitySignRequests() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let signer = HoldingAuditProducerSigner(privateKey: privateKey)
        let chain = AuditProducerChain(stateStore: volatileStateStore())
        let flowExp = expectation(description: "flow completion")
        let availabilityExp = expectation(description: "availability completion")
        var flowResult: Result<IpcMessage, AuditProducerSigningError>?
        var availabilityResult: Result<IpcMessage, AuditProducerSigningError>?
        let enforcement = EnforcementAvailabilitySnapshotBody(
            leaseState: "live",
            leaseReason: "ok",
            manifestState: "applied",
            manifestSignatureB64url: "manifest-signature",
            providerBound: true,
            producerClaimedAt: "2025-10-09T08:53:20Z"
        )

        chain.buildSignedFlowDecision(
            outcome: .allow(matchedRuleId: "r-allow-1"),
            flow: makeFlow(host: "api.openai.com"),
            recordedAt: Date(timeIntervalSince1970: 1_760_000_000),
            signer: signer
        ) { r in
            flowResult = r
            flowExp.fulfill()
        }
        chain.buildSignedAvailabilityReport(
            enforcement: enforcement,
            fortressId: "agent-7",
            reportedAt: Date(timeIntervalSince1970: 1_760_000_001),
            signer: signer
        ) { r in
            availabilityResult = r
            availabilityExp.fulfill()
        }
        let activeDeadline = Date().addingTimeInterval(1)
        while signer.replies.count < 1 && Date() < activeDeadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.01))
        }
        XCTAssertEqual(
            signer.replies.count,
            1,
            "only one audit-producer sign call may be in flight before the cursor advances"
        )
        signer.resolve(0)
        wait(for: [flowExp], timeout: 2)
        guard case .success(.flowDecisionRecorded(let flowBody))? = flowResult else {
            return XCTFail("first flow should sign successfully before availability starts")
        }
        let flowProducer = try XCTUnwrap(flowBody.producer)
        XCTAssertEqual(flowProducer.seq, 0)

        let queuedDeadline = Date().addingTimeInterval(1)
        while signer.replies.count < 2 && Date() < queuedDeadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.01))
        }
        XCTAssertEqual(
            signer.replies.count,
            2,
            "queued availability signing should start after the flow advances the cursor"
        )
        signer.resolve(1)
        wait(for: [availabilityExp], timeout: 2)
        guard case .success(.enforcementAvailabilityReport(let availabilityBody))? = availabilityResult else {
            return XCTFail("queued availability report should sign successfully")
        }
        let availabilityProducer = try XCTUnwrap(availabilityBody.producer)
        XCTAssertEqual(availabilityProducer.seq, 1)
        XCTAssertEqual(
            availabilityProducer.priorSha256Hex,
            hashSignedBody(flowProducer.eventCanonicalJson)
        )
    }

    func test_auditProducerChain_failsLoudlyWhenSigningQueueOverflows() {
        let privateKey = Curve25519.Signing.PrivateKey()
        let signer = HoldingAuditProducerSigner(privateKey: privateKey)
        let chain = AuditProducerChain(
            maxQueuedSigningJobs: 1,
            stateStore: volatileStateStore()
        )
        let firstExp = expectation(description: "active signing completion")
        let queuedExp = expectation(description: "queued signing completion")
        let overflowExp = expectation(description: "overflow signing completion")
        var queuedSeq: UInt64?
        var overflowResult: Result<IpcMessage, AuditProducerSigningError>?

        chain.buildSignedFlowDecision(
            outcome: .allow(matchedRuleId: "r-active"),
            flow: makeFlow(host: "api.active.example"),
            signer: signer
        ) { _ in
            firstExp.fulfill()
        }
        chain.buildSignedFlowDecision(
            outcome: .allow(matchedRuleId: "r-queued"),
            flow: makeFlow(host: "api.queued.example"),
            signer: signer
        ) { r in
            if case .success(.flowDecisionRecorded(let body)) = r {
                queuedSeq = body.producer?.seq
            }
            queuedExp.fulfill()
        }
        chain.buildSignedFlowDecision(
            outcome: .allow(matchedRuleId: "r-overflow"),
            flow: makeFlow(host: "api.overflow.example"),
            signer: signer
        ) { r in
            overflowResult = r
            overflowExp.fulfill()
        }

        wait(for: [overflowExp], timeout: 2)
        guard case .failure(.signingQueueFull(let maxQueued, let droppedCount))? = overflowResult else {
            return XCTFail("overflow must fail loudly as signingQueueFull")
        }
        XCTAssertEqual(maxQueued, 1)
        XCTAssertEqual(droppedCount, 1)

        let activeDeadline = Date().addingTimeInterval(1)
        while signer.replies.count < 1 && Date() < activeDeadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.01))
        }
        XCTAssertEqual(signer.replies.count, 1)
        signer.resolve(0)
        wait(for: [firstExp], timeout: 2)

        let queuedDeadline = Date().addingTimeInterval(1)
        while signer.replies.count < 2 && Date() < queuedDeadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.01))
        }
        XCTAssertEqual(signer.replies.count, 2)
        signer.resolve(1)
        wait(for: [queuedExp], timeout: 2)
        XCTAssertEqual(queuedSeq, 1)
    }

    func test_auditProducerChain_chainsFlowAndAvailabilityOverSignedWalBody() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let signer = ImmediateAuditProducerSigner(privateKey: privateKey)
        let chain = AuditProducerChain(stateStore: volatileStateStore())

        func hashSignedBody(_ canonicalJson: String) -> String {
            let digest = SHA256.hash(data: Data(canonicalJson.utf8))
            return digest.map { String(format: "%02x", $0) }.joined()
        }

        func signFlow(_ label: String) throws -> AuditProducerSignatureBody {
            let exp = expectation(description: label)
            var result: Result<IpcMessage, AuditProducerSigningError>?
            chain.buildSignedFlowDecision(
                outcome: .allow(matchedRuleId: "r-allow"),
                flow: makeFlow(),
                recordedAt: Date(timeIntervalSince1970: 1_760_000_000),
                signer: signer
            ) { r in
                result = r
                exp.fulfill()
            }
            wait(for: [exp], timeout: 2)
            let message = try XCTUnwrap(result).get()
            guard case .flowDecisionRecorded(let body) = message else {
                XCTFail("expected signed flowDecisionRecorded")
                throw NSError(domain: "ExtensionDispatcherTests", code: 1)
            }
            return try XCTUnwrap(body.producer)
        }

        func signAvailability(_ label: String) throws -> AuditProducerSignatureBody {
            let enforcement = EnforcementAvailabilitySnapshotBody(
                leaseState: "live",
                leaseReason: "ok",
                manifestState: "applied",
                manifestSignatureB64url: "manifest-signature",
                providerBound: true,
                producerClaimedAt: "2025-10-09T08:53:20Z"
            )
            let exp = expectation(description: label)
            var result: Result<IpcMessage, AuditProducerSigningError>?
            chain.buildSignedAvailabilityReport(
                enforcement: enforcement,
                fortressId: "agent-7",
                reportedAt: Date(timeIntervalSince1970: 1_760_000_001),
                signer: signer
            ) { r in
                result = r
                exp.fulfill()
            }
            wait(for: [exp], timeout: 2)
            let message = try XCTUnwrap(result).get()
            guard case .enforcementAvailabilityReport(let body) = message else {
                XCTFail("expected signed enforcementAvailabilityReport")
                throw NSError(domain: "ExtensionDispatcherTests", code: 2)
            }
            return try XCTUnwrap(body.producer)
        }

        let flowProducer = try signFlow("signed flow")
        XCTAssertEqual(flowProducer.seq, 0)
        XCTAssertNil(flowProducer.priorSha256Hex)

        let availabilityProducer = try signAvailability("signed availability")
        XCTAssertEqual(availabilityProducer.seq, 1)
        XCTAssertEqual(
            availabilityProducer.priorSha256Hex,
            hashSignedBody(flowProducer.eventCanonicalJson),
            "availability prior must chain from the flow decision's signed WAL body"
        )

        let nextFlowProducer = try signFlow("signed flow after availability")
        XCTAssertEqual(nextFlowProducer.seq, 2)
        XCTAssertEqual(
            nextFlowProducer.priorSha256Hex,
            hashSignedBody(availabilityProducer.eventCanonicalJson),
            "flow prior must chain from the availability report's signed WAL body"
        )
    }

}
