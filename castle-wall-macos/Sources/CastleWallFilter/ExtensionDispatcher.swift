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
            recordDroppedVerdict(state: state)
            return
        }
        maybeEmitProviderUnboundAudit(trigger: "verdict")

        switch outcome {
        case .allow, .drop:
            if let auditProducerSigner {
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
                        CastleWallLog.ipc.notice(
                            "audit producer signing failed; dropping signed verdict notification reason=\(String(describing: error))"
                        )
                    }
                }
                return
            }
            guard let message = IPCBridgeNotifications.buildFlowDecisionRecorded(
                outcome: outcome,
                flow: flow
            ) else {
                return
            }
            ipcClient.send(message, onError: handleSendError)
        case .uncertain:
            let message = IPCBridgeNotifications.buildFlowPendingApproval(flow: flow)
            ipcClient.send(message, onError: handleSendError)
        }
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
