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

    private let engine: FlowEvaluatorEngine
    private let ipcClient: IPCClient
    private let manifestStore: ManifestStore
    private let flowCache: FlowCache
    private let sendErrorHandler: SendErrorHandler

    /// Optional override for tests that want to observe the listener
    /// without exercising the live IPC client. Production callers leave
    /// this nil.
    private var inboundListenerOverride: IPCMessageListener?

    public init(
        engine: FlowEvaluatorEngine,
        ipcClient: IPCClient,
        sendErrorHandler: @escaping SendErrorHandler = ExtensionDispatcher.defaultSendErrorHandler
    ) {
        self.engine = engine
        self.ipcClient = ipcClient
        self.manifestStore = engine.manifestStore
        self.flowCache = engine.flowCache
        self.sendErrorHandler = sendErrorHandler
    }

    /// Default send-error handler logs to the IPC subsystem and swallows
    /// the error. The verdict path must NEVER block on IPC liveness.
    public static let defaultSendErrorHandler: SendErrorHandler = { error in
        CastleWallLog.ipc.notice(
            "ExtensionDispatcher send failed (non-fatal): \(String(describing: error))"
        )
    }

    // MARK: - Lifecycle

    /// Complete the IPC handshake, register the inbound listener, and
    /// send the initial `manifest_subscribe` request. Returns once the
    /// handshake has completed; the subscribe request is fire-and-forget.
    ///
    /// On handshake failure the dispatcher does NOT throw; the
    /// FilterProvider keeps a refuse-to-load fallback and evaluates
    /// against an empty manifest (fail-closed). Callers may inspect
    /// `isStarted` to know whether the IPC channel is live.
    @discardableResult
    public func start() async -> Bool {
        do {
            _ = try await ipcClient.start()
        } catch {
            CastleWallLog.lifecycle.notice(
                "ExtensionDispatcher start failed: \(String(describing: error))"
            )
            return false
        }
        ipcClient.setMessageListener { [weak self] message in
            self?.handleInbound(message)
        }
        // Initial subscribe so the server immediately pushes the current
        // manifest snapshot. Fire-and-forget; if it fails, the listener
        // is still installed and a later manifest_updated push will land.
        ipcClient.send(
            IPCBridgeNotifications.buildSubscribeRequest(),
            onError: sendErrorHandler
        )
        isStartedFlag = true
        return true
    }

    /// True once `start()` has completed the handshake successfully.
    public private(set) var isStartedFlag: Bool = false

    public var isStarted: Bool { isStartedFlag }

    /// Close the underlying IPC client. Idempotent.
    public func stop() {
        ipcClient.setMessageListener(nil)
        ipcClient.close()
        isStartedFlag = false
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
        switch outcome {
        case .allow, .drop:
            guard let message = IPCBridgeNotifications.buildFlowDecisionRecorded(
                outcome: outcome,
                flow: flow
            ) else {
                return
            }
            ipcClient.send(message, onError: sendErrorHandler)
        case .uncertain:
            let message = IPCBridgeNotifications.buildFlowPendingApproval(flow: flow)
            ipcClient.send(message, onError: sendErrorHandler)
        }
    }

    // MARK: - Inbound (called by the IPCClient listener)

    /// Handle a post-handshake inbound message. Public so tests can drive
    /// it directly without exercising the IPC client.
    public func handleInbound(_ message: IpcMessage) {
        switch message {
        case .manifestUpdated:
            // Apply via the existing helper to keep store + cache invariants paired.
            _ = IPCBridgeNotifications.applyManifestUpdated(
                message: message,
                store: manifestStore,
                cache: flowCache
            )
        case .decisionResponse:
            // Operator-approval / -deny resume path; round-trip wiring
            // for uncertain-flow resume lands in the Alpha-4 install
            // scope alongside `resumeFlow(_:with:)` on NEFilterDataProvider.
            // Today the dispatcher records receipt for observability and
            // drops; the FilterProvider's `.uncertain` flows already use
            // `pause()` per the existing translation.
            CastleWallLog.lifecycle.info(
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
}
