//
// ExtensionDispatcher.swift
//
// Bridge between the NEFilter decision substrate and the IPC bridge.
//
// Phase 1 (Alpha-1 + Alpha-2) shipped the pure substrate:
//   - FlowEvaluatorEngine (manifest + cache + verdict)
//   - IPCBridgeNotifications (builders for outbound + appliers for inbound)
//   - IPCClient (UDS connect + handshake; foundation-scope ack)
// but nothing wired the two ends together. Phase 2 (this build) is that
// wiring: a dispatcher that owns the IPCClient lifecycle, subscribes to
// manifest_updated frames, and emits flow_decision_recorded /
// flow_pending_approval for every verdict the FilterProvider produces.
//
// Lifecycle:
//   - `start()`: open the IPC connection, complete the handshake, register
//     a post-handshake message listener that routes inbound frames through
//     `IPCBridgeNotifications.applyManifestUpdated(...)`, then send a
//     `manifest_subscribe` request so the server pushes the initial
//     snapshot.
//   - `notifyVerdict(_, for:)`: called by the FilterProvider from
//     `handleNewFlow(_:)` after each verdict. Builds the matching outbound
//     IpcMessage and writes it via the IPCClient. Fire-and-forget; errors
//     are logged but do not block the verdict path.
//   - `stop()`: close the IPC connection and release the listener.
//
// Thread safety: the dispatcher hands work to the IPCClient's internal
// queue for sends, and the listener callback runs on that queue. The
// FilterProvider's verdict path calls `notifyVerdict` directly from the
// NEFilterDataProvider callback queue; the call is fire-and-forget so it
// does NOT block the framework callback on send completion.
//
// Castle-walking: emission is observation-side, not decision-side. The
// verdict has already been returned to the framework by the time the IPC
// notification fires; a slow/broken IPC transport NEVER delays a verdict.
// This preserves the <10ms-p99-on-allowed-traffic invariant even when the
// server is unreachable.
//

import Foundation
import CastleWallIPC

/// Bridges the FlowEvaluatorEngine + FilterProvider to the IPCClient.
public final class ExtensionDispatcher {

    /// Closure type the IPC client returns on send failures.
    public typealias SendErrorHandler = (IPCClientError) -> Void

    public enum ConnectionState: Equatable {
        case disconnected
        case handshaking
        case connected
        case retrying
        case deadChannel
    }

    public struct BindingState: Equatable {
        public let connected: Bool
        public let manifestReceived: Bool
        public let armLeaseReceived: Bool

        public var bound: Bool {
            connected && manifestReceived && armLeaseReceived
        }
    }

    private let engine: FlowEvaluatorEngine
    private let ipcClient: IPCClient
    private let manifestStore: ManifestStore
    private let flowCache: FlowCache
    private let sendErrorHandler: SendErrorHandler
    private let auditProducerSigner: AuditProducerSigning?
    private let auditProducerChain: AuditProducerChain

    private let stateQueue = DispatchQueue(
        label: "ai.sanctuaryprotocol.castle-wall.extension-dispatcher.state"
    )
    private var connectionStateValue: ConnectionState = .disconnected
    private var retryDelaySeconds: TimeInterval = 1.0
    private var retryTimer: DispatchSourceTimer?
    private var listenersInstalled = false
    private var isStopping = false
    private var verdictsDroppedDeadChannel = 0
    private var lastVerdictDropLogAt = Date.distantPast
    private var manifestReceived = false
    private var armLeaseReceived = false
    private var providerUnboundAuditSent = false
    private var connectedFortressId: String?
    private var unboundTimer: DispatchSourceTimer?
    /// True once `start()` has been invoked at least once. Gates the
    /// lazy-reconnect path in `notifyVerdict`: a dispatcher that has never
    /// been started (the pristine `.disconnected` state used by unit tests
    /// and by a not-yet-bootstrapped provider) must NOT spin up a connection
    /// attempt from the verdict callback; it only retries a channel that was
    /// previously brought up and has since degraded.
    private var hasEverStarted = false
    /// Greppable prefix for the Slice-M audit-emission drop-path probes.
    /// The signed-host engage drill runs
    /// `log stream --predicate 'process == "CastleWallExtension"'` and greps
    /// this prefix to learn EXACTLY which of the three drop paths fired when
    /// no per-flow `producer_signed` audit entry reaches the daemon consumer.
    /// Never log key material, signatures, or raw destination payloads here.
    private static let auditDropLogPrefix = "[slice-m-audit-drop]"

    private static let initialRetryDelaySeconds: TimeInterval = 1.0
    private static let maxRetryDelaySeconds: TimeInterval = 30.0
    private static let retryJitterPercent: Double = 0.15
    private static let unboundAuditDelaySeconds: TimeInterval = 5.0

    public init(
        engine: FlowEvaluatorEngine,
        ipcClient: IPCClient,
        auditProducerSigner: AuditProducerSigning? = XpcAuditProducerSigner(),
        auditProducerChain: AuditProducerChain = AuditProducerChain(),
        sendErrorHandler: @escaping SendErrorHandler = ExtensionDispatcher.defaultSendErrorHandler
    ) {
        self.engine = engine
        self.ipcClient = ipcClient
        self.manifestStore = engine.manifestStore
        self.flowCache = engine.flowCache
        self.auditProducerSigner = auditProducerSigner
        self.auditProducerChain = auditProducerChain
        self.sendErrorHandler = sendErrorHandler
    }

    /// Default send-error handler logs to the IPC subsystem and swallows
    /// the error. The verdict path must NEVER block on IPC liveness.
    public static let defaultSendErrorHandler: SendErrorHandler = { error in
        switch error {
        case .sendBeforeHandshake:
            CastleWallLog.ipc.notice("ExtensionDispatcher send failed: sendBeforeHandshake")
        case .transportClosed:
            CastleWallLog.ipc.notice("ExtensionDispatcher send failed: transportClosed")
        case .sendFailed(let reason):
            CastleWallLog.ipc.notice("ExtensionDispatcher send failed: sendFailed reason=\(reason)")
        case .notStarted:
            CastleWallLog.ipc.notice("ExtensionDispatcher send failed: notStarted")
        case .alreadyStarted:
            CastleWallLog.ipc.notice("ExtensionDispatcher send failed: alreadyStarted")
        case .connectFailed(let reason):
            CastleWallLog.ipc.notice("ExtensionDispatcher send failed: connectFailed reason=\(reason)")
        case .framingError(let reason):
            CastleWallLog.ipc.notice("ExtensionDispatcher send failed: framingError reason=\(reason)")
        case .envelopeMalformed(let reason):
            CastleWallLog.ipc.notice("ExtensionDispatcher send failed: envelopeMalformed reason=\(reason)")
        case .handshakeTimeout:
            CastleWallLog.ipc.notice("ExtensionDispatcher send failed: handshakeTimeout")
        case .handshakeRejected(let reason):
            CastleWallLog.ipc.notice("ExtensionDispatcher send failed: handshakeRejected reason=\(reason)")
        case .socketPathTooLong(let maxBytes, let actual):
            CastleWallLog.ipc.notice(
                "ExtensionDispatcher send failed: socketPathTooLong actual=\(actual) max=\(maxBytes)"
            )
        }
    }

    // MARK: - Lifecycle

    /// Complete the IPC handshake, register the inbound listener, and
    /// send the initial `manifest_subscribe` request. Returns once the
    /// handshake attempt has completed.
    @discardableResult
    public func start() async -> Bool {
        _ = IPCBridgeNotifications.recoverPersistedManifest(
            store: manifestStore,
            cache: flowCache,
            pinnedPublicKey: ipcClient.pinnedPublicKeyBytes,
            engine: engine
        )

        stateQueue.sync {
            isStopping = false
            hasEverStarted = true
        }
        installClientListenersIfNeeded()

        return await attemptStartAndSubscribe(trigger: "initial")
    }

    /// True once `start()` has completed the handshake successfully.
    public var isStarted: Bool {
        return connectionState == .connected
    }

    public var connectionState: ConnectionState {
        return stateQueue.sync { connectionStateValue }
    }

    public var bindingState: BindingState {
        return stateQueue.sync {
            BindingState(
                connected: connectionStateValue == .connected,
                manifestReceived: manifestReceived,
                armLeaseReceived: armLeaseReceived
            )
        }
    }

    /// Close the underlying IPC client. Idempotent.
    public func stop() {
        stateQueue.sync {
            isStopping = true
            retryTimer?.cancel()
            retryTimer = nil
            unboundTimer?.cancel()
            unboundTimer = nil
            connectionStateValue = .disconnected
            retryDelaySeconds = Self.initialRetryDelaySeconds
            manifestReceived = false
            armLeaseReceived = false
            connectedFortressId = nil
        }
        ipcClient.setTransportClosedListener(nil)
        ipcClient.setMessageListener(nil)
        ipcClient.close()
    }

    // MARK: - Outbound (called from FilterProvider verdict path)

    /// Fire-and-forget notification after a verdict has been returned.
    /// The flow descriptor + outcome together build either a
    /// `flow_decision_recorded` (allow / drop) or a
    /// `flow_pending_approval` (uncertain). The verdict has already been
    /// returned to NEFilterDataProvider by the time this fires, so a
    /// slow IPC channel never delays the framework decision.
    public func notifyVerdict(
        _ outcome: EvaluationOutcome,
        for flow: FilterFlowDescriptor
    ) {
        let state = connectionState
        guard state == .connected else {
            // DROP-PATH 2 (disconnected-dispatcher). The audit-reporting
            // channel is not connected, so the per-flow verdict cannot be
            // emitted. Log the ACTUAL connection-state discriminator so the
            // drill can tell a genuinely-down channel apart from a not-yet-
            // bound one. Then attempt a lazy (re)connect so a verdict that
            // fires after the daemon comes up rebinds the channel instead of
            // dropping forever (the leading 06-26/06-28 hypothesis: the
            // extension activated before the audit channel existed and never
            // rebound). The current verdict is still dropped (fail-closed,
            // never blocks the framework callback); the NEXT verdict after a
            // successful rebind emits normally.
            CastleWallLog.lifecycle.error(
                "\(Self.auditDropLogPrefix) path=disconnected-dispatcher connection_state=\(String(describing: state)) outcome=\(Self.outcomeLabel(outcome)) decision: dropping per-flow audit emission, attempting lazy rebind"
            )
            recordDroppedVerdict(state: state)
            maybeLazyReconnect(reason: "verdict-while-\(String(describing: state))")
            return
        }
        maybeEmitProviderUnboundAudit(trigger: "verdict")

        switch outcome {
        case .allow, .drop:
            guard let auditProducerSigner else {
                // DROP-PATH 1 (nil-signer / nil-dispatcher). In production the
                // FilterProvider ALWAYS constructs the dispatcher with a real
                // `XpcAuditProducerSigner`, so this branch firing means the
                // signer was never assigned. A pinned-key consumer must reject
                // unsigned enforcement evidence, so we DROP rather than fall
                // back to an unsigned emit (hard security invariant). The
                // unsigned builder below exists ONLY for the no-signer unit
                // tests; it must never be reached on a signing-extension build.
                CastleWallLog.lifecycle.error(
                    "\(Self.auditDropLogPrefix) path=nil-signer reason=audit-producer-signer-not-assigned outcome=\(Self.outcomeLabel(outcome)) decision: dropping per-flow audit emission (no unsigned fallback)"
                )
                guard let message = IPCBridgeNotifications.buildFlowDecisionRecorded(
                    outcome: outcome,
                    flow: flow
                ) else {
                    return
                }
                ipcClient.send(message, onError: handleSendError)
                return
            }
            auditProducerChain.buildSignedFlowDecision(
                outcome: outcome,
                flow: flow,
                signer: auditProducerSigner
            ) { [weak self] result in
                guard let self else { return }
                switch result {
                case .success(let message):
                    self.ipcClient.send(message, onError: self.handleSendError)
                case .failure(let error):
                    // DROP-PATH 3 (audit-producer signing failure). The XPC
                    // call to the root helper's audit-producer Mach service
                    // failed (helper unreachable, key not yet provisioned, or
                    // the sign call errored). Dropping on a GENUINE signing
                    // failure is CORRECT fail-closed behavior: a pinned-key
                    // consumer must reject unsigned evidence, so we never
                    // synthesize an unsigned emit. The fix is to make signing
                    // SUCCEED, not to bypass it; now the drop is LOGGED with
                    // the underlying error so the drill sees this path fire.
                    CastleWallLog.lifecycle.error(
                        "\(Self.auditDropLogPrefix) path=signing-failure reason=\(Self.signingErrorLabel(error)) outcome=\(Self.outcomeLabel(outcome)) decision: dropping per-flow audit emission (fail-closed, no unsigned fallback)"
                    )
                }
            }
        case .uncertain:
            let message = IPCBridgeNotifications.buildFlowPendingApproval(flow: flow)
            ipcClient.send(message, onError: handleSendError)
        }
    }

    /// Human-readable outcome label for the drop-path probes. Carries only
    /// the verdict class (allow / drop / uncertain) and the matched-rule id,
    /// never destination payloads or key material.
    private static func outcomeLabel(_ outcome: EvaluationOutcome) -> String {
        switch outcome {
        case .allow(let ruleId):
            return "allow rule_id=\(ruleId)"
        case .drop(let ruleId):
            return "drop rule_id=\(ruleId ?? "none")"
        case .uncertain:
            return "uncertain"
        }
    }

    /// Compact, key-material-free label for an audit-producer signing error,
    /// so the drill can distinguish "helper unreachable" from "empty
    /// signature" from "canonicalization failed" without dumping a payload.
    private static func signingErrorLabel(_ error: AuditProducerSigningError) -> String {
        switch error {
        case .unsupportedOutcome:
            return "unsupported-outcome"
        case .canonicalizationFailed:
            return "canonicalization-failed"
        case .signerUnavailable(let detail):
            return "signer-unavailable(\(detail))"
        case .emptySignature:
            return "empty-signature"
        }
    }

    /// If the channel was previously brought up (`start()` has run) but is now
    /// degraded (`retrying` / `deadChannel`), kick a reconnect attempt so a
    /// verdict that arrives after the daemon comes up rebinds the audit
    /// channel rather than dropping forever. Never fires from the pristine
    /// `.disconnected` state (a never-started dispatcher), so unit tests that
    /// drive `notifyVerdict` without `start()` keep their `.disconnected`
    /// invariant, and a not-yet-bootstrapped provider does not race its own
    /// bootstrap. The reconnect-kick is suppressed while a retry timer is
    /// already pending, so steady verdict traffic cannot starve the scheduled
    /// attempt; `attemptStartAndSubscribe` guards on `socketFD`/`isStopping`.
    private func maybeLazyReconnect(reason: String) {
        let shouldReconnect: Bool = stateQueue.sync {
            guard hasEverStarted, !isStopping else { return false }
            switch connectionStateValue {
            case .deadChannel, .retrying:
                // Kick a reconnect ONLY when none is already scheduled. A verdict
                // is live demand for the audit channel, but resetting an in-flight
                // retry timer on every verdict STARVES the reconnect under load:
                // an armed wall sees constant traffic, so the timer is cancelled
                // and rescheduled faster than its delay can ever elapse and
                // `attemptStartAndSubscribe` never runs (drill 2026-06-29: 0
                // producer-signed entries, "reconnect scheduled" spam, zero
                // "connected"/"start failed" across 2h). When a retry timer is
                // already pending we let it fire; only a timerless degraded state
                // (e.g. a fresh transport close) collapses the backoff and kicks
                // a fresh attempt.
                guard retryTimer == nil else { return false }
                retryDelaySeconds = Self.initialRetryDelaySeconds
                return true
            case .disconnected, .handshaking, .connected:
                // `.disconnected` here means never-started or cleanly stopped;
                // `.handshaking` means an attempt is already in flight;
                // `.connected` is handled by the caller's happy path.
                return false
            }
        }
        guard shouldReconnect else { return }
        CastleWallLog.lifecycle.notice(
            "\(Self.auditDropLogPrefix) lazy-rebind requested; reason=\(reason)"
        )
        scheduleReconnect(reason: "lazy-rebind (\(reason))")
    }

    // MARK: - Inbound (called by the IPCClient listener)

    /// Handle a post-handshake inbound message. Public so tests can drive
    /// it directly without exercising the IPC client.
    public func handleInbound(_ message: IpcMessage) {
        switch message {
        case .armLease(let body):
            engine.armLease.update(
                ArmLeaseUpdate(
                    armed: body.armed,
                    revoked: body.revoked,
                    ttlSeconds: body.ttlSeconds,
                    heartbeatIntervalSeconds: body.heartbeatIntervalSeconds
                )
            )
            stateQueue.sync {
                armLeaseReceived = true
                cancelUnboundTimerIfBoundLocked()
            }
            flowCache.clear()
        case .manifestUpdated:
            // Apply via the existing helper to keep store + cache invariants paired.
            _ = IPCBridgeNotifications.applyManifestUpdated(
                message: message,
                store: manifestStore,
                cache: flowCache,
                pinnedPublicKey: ipcClient.pinnedPublicKeyBytes,
                engine: engine
            )
            stateQueue.sync {
                manifestReceived = true
                cancelUnboundTimerIfBoundLocked()
            }
        case .decisionResponse:
            // Operator-approval / -deny resume path; round-trip wiring
            // for uncertain-flow resume lands in the Alpha-4 install
            // scope alongside `resumeFlow(_:with:)` on NEFilterDataProvider.
            CastleWallLog.lifecycle.notice(
                "decision_response received; resume path lands in Alpha-4"
            )
        default:
            // Other inbound types (audit_drain_request, status_request,
            // etc.) are not consumed by the extension side today; log
            // and drop so unknown traffic does not silently desync.
            CastleWallLog.ipc.notice(
                "unhandled inbound message type; dropping"
            )
        }
    }

    private func installClientListenersIfNeeded() {
        let shouldInstall = stateQueue.sync { () -> Bool in
            if listenersInstalled { return false }
            listenersInstalled = true
            return true
        }
        guard shouldInstall else { return }

        ipcClient.setMessageListener { [weak self] message in
            self?.handleInbound(message)
        }
        ipcClient.setTransportClosedListener { [weak self] error in
            self?.handleTransportClosed(error)
        }
    }

    private func attemptStartAndSubscribe(trigger: String) async -> Bool {
        let shouldStop = stateQueue.sync { isStopping }
        guard !shouldStop else {
            return false
        }

        updateConnectionState(.handshaking)
        do {
            let identity = try await ipcClient.start()
            stateQueue.sync {
                retryDelaySeconds = Self.initialRetryDelaySeconds
                retryTimer?.cancel()
                retryTimer = nil
                connectionStateValue = .connected
                manifestReceived = false
                armLeaseReceived = false
                providerUnboundAuditSent = false
                connectedFortressId = identity.fortressId
            }
            ipcClient.send(
                IPCBridgeNotifications.buildSubscribeRequest(),
                onError: handleSendError
            )
            scheduleUnboundAuditCheck(trigger: trigger)
            CastleWallLog.lifecycle.notice("ExtensionDispatcher connected; trigger=\(trigger)")
            return true
        } catch {
            let ipcError = normalizeError(error)
            logStartFailure(ipcError)
            updateConnectionState(.deadChannel)
            scheduleReconnect(reason: "start failure (\(trigger))")
            return false
        }
    }

    private func logStartFailure(_ error: IPCClientError) {
        switch error {
        case .alreadyStarted:
            CastleWallLog.lifecycle.error("ExtensionDispatcher start failed: alreadyStarted")
        case .notStarted:
            CastleWallLog.lifecycle.error("ExtensionDispatcher start failed: notStarted")
        case .transportClosed:
            CastleWallLog.lifecycle.error("ExtensionDispatcher start failed: transportClosed")
        case .connectFailed(let reason):
            CastleWallLog.lifecycle.error("ExtensionDispatcher start failed: connectFailed reason=\(reason)")
        case .framingError(let reason):
            CastleWallLog.lifecycle.error("ExtensionDispatcher start failed: framingError reason=\(reason)")
        case .envelopeMalformed(let reason):
            CastleWallLog.lifecycle.error("ExtensionDispatcher start failed: envelopeMalformed reason=\(reason)")
        case .handshakeTimeout:
            CastleWallLog.lifecycle.error("ExtensionDispatcher start failed: handshakeTimeout")
        case .handshakeRejected(let reason):
            CastleWallLog.lifecycle.error("ExtensionDispatcher start failed: handshakeRejected reason=\(reason)")
        case .socketPathTooLong(let maxBytes, let actual):
            CastleWallLog.lifecycle.error(
                "ExtensionDispatcher start failed: socketPathTooLong actual=\(actual) max=\(maxBytes)"
            )
        case .sendFailed(let reason):
            CastleWallLog.lifecycle.error("ExtensionDispatcher start failed: sendFailed reason=\(reason)")
        case .sendBeforeHandshake:
            CastleWallLog.lifecycle.error("ExtensionDispatcher start failed: sendBeforeHandshake")
        }
    }

    private func scheduleUnboundAuditCheck(trigger: String) {
        stateQueue.sync {
            unboundTimer?.cancel()
            let timer = DispatchSource.makeTimerSource(queue: stateQueue)
            timer.schedule(deadline: .now() + Self.unboundAuditDelaySeconds)
            timer.setEventHandler { [weak self] in
                self?.emitProviderUnboundAuditLocked(trigger: "bind-timeout-\(trigger)")
            }
            unboundTimer = timer
            timer.resume()
        }
    }

    private func cancelUnboundTimerIfBoundLocked() {
        guard connectionStateValue == .connected && manifestReceived && armLeaseReceived else {
            return
        }
        unboundTimer?.cancel()
        unboundTimer = nil
        CastleWallLog.lifecycle.notice("ExtensionDispatcher bound: manifest_received=true arm_lease_received=true")
    }

    private func maybeEmitProviderUnboundAudit(trigger: String) {
        stateQueue.sync {
            emitProviderUnboundAuditLocked(trigger: trigger)
        }
    }

    private func emitProviderUnboundAuditLocked(trigger: String) {
        guard connectionStateValue == .connected else {
            return
        }
        guard !(manifestReceived && armLeaseReceived) else {
            return
        }
        guard !providerUnboundAuditSent else {
            return
        }
        providerUnboundAuditSent = true
        let fortressId = connectedFortressId ?? "unknown"
        CastleWallLog.lifecycle.error(
            "ExtensionDispatcher provider_unbound: trigger=\(trigger) manifest_received=\(self.manifestReceived) arm_lease_received=\(self.armLeaseReceived)"
        )
        ipcClient.send(
            ExtensionDispatcher.buildProviderUnboundAudit(
                fortressId: fortressId,
                trigger: trigger,
                manifestReceived: manifestReceived,
                armLeaseReceived: armLeaseReceived
            ),
            onError: handleSendError
        )
    }

    static func buildProviderUnboundAudit(
        fortressId: String,
        trigger: String,
        manifestReceived: Bool,
        armLeaseReceived: Bool,
        timestamp: String = ExtensionDispatcher.isoTimestamp()
    ) -> IpcMessage {
        return .auditEmit(event: .object([
            "schema_version": .number(1),
            "layer": .string("l1"),
            "timestamp": .string(timestamp),
            "fortress_id": .string(fortressId),
            "event_type": .string("provider_unbound"),
            "agent": .null,
            "destination": .null,
            "decision": .null,
            "rule_id": .null,
            "details": .object([
                "source": .string("macos_extension"),
                "trigger": .string(trigger),
                "manifest_received": .bool(manifestReceived),
                "arm_lease_received": .bool(armLeaseReceived)
            ])
        ]))
    }

    private static func isoTimestamp() -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: Date())
    }

    private func normalizeError(_ error: Error) -> IPCClientError {
        if let ipcError = error as? IPCClientError {
            return ipcError
        }
        return .sendFailed(String(describing: error))
    }

    private func handleTransportClosed(_ error: IPCClientError) {
        let shouldStop = stateQueue.sync { isStopping }
        guard !shouldStop else { return }

        updateConnectionState(.deadChannel)
        CastleWallLog.lifecycle.error(
            "ExtensionDispatcher transport dropped; scheduling reconnect reason=\(String(describing: error))"
        )
        scheduleReconnect(reason: "transport dropped")
    }

    private func handleSendError(_ error: IPCClientError) {
        sendErrorHandler(error)
        switch error {
        case .transportClosed, .sendFailed:
            ipcClient.close()
            handleTransportClosed(error)
        default:
            return
        }
    }

    private func scheduleReconnect(reason: String) {
        stateQueue.async {
            guard !self.isStopping else { return }

            self.retryTimer?.cancel()
            self.retryTimer = nil
            self.unboundTimer?.cancel()
            self.unboundTimer = nil

            let base = self.retryDelaySeconds
            let jitterRange = base * Self.retryJitterPercent
            let jitter = Double.random(in: -jitterRange...jitterRange)
            let delay = max(0.5, min(Self.maxRetryDelaySeconds, base + jitter))
            self.retryDelaySeconds = min(Self.maxRetryDelaySeconds, max(base * 2.0, 1.0))
            self.connectionStateValue = .retrying

            let delayText = String(format: "%.2f", delay)
            CastleWallLog.lifecycle.notice(
                "ExtensionDispatcher reconnect scheduled in \(delayText)s; reason=\(reason)"
            )

            let timer = DispatchSource.makeTimerSource(queue: self.stateQueue)
            timer.schedule(deadline: .now() + delay)
            timer.setEventHandler { [weak self] in
                guard let self else { return }
                self.retryTimer = nil
                Task {
                    _ = await self.attemptStartAndSubscribe(trigger: "retry")
                }
            }
            self.retryTimer = timer
            timer.resume()
        }
    }

    private func updateConnectionState(_ newValue: ConnectionState) {
        stateQueue.sync {
            connectionStateValue = newValue
            if newValue != .connected {
                unboundTimer?.cancel()
                unboundTimer = nil
            }
        }
    }

    private func recordDroppedVerdict(state: ConnectionState) {
        stateQueue.async {
            self.verdictsDroppedDeadChannel += 1
            let now = Date()
            guard now.timeIntervalSince(self.lastVerdictDropLogAt) >= 60 else {
                return
            }
            CastleWallLog.ipc.notice(
                "ExtensionDispatcher dropped \(self.verdictsDroppedDeadChannel) verdict notifications while state=\(String(describing: state))"
            )
            self.lastVerdictDropLogAt = now
            self.verdictsDroppedDeadChannel = 0
        }
    }
}
