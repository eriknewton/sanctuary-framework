//
// IPCClient.swift
//
// UDS client speaking the Castle Wall JSON-RPC over LSP-style framing. The
// macOS extension is the *daemon* in the protocol roles, but the OS-level
// connection is initiated FROM the extension TOWARD the Sanctuary main
// process: main hosts the UDS listener at a path the extension resolves via
// `SocketPath.resolve`. This mirrors the Linux topology where main is the
// approver / audit consumer and the kernel-binding daemon is the egress
// chokepoint.
//
// Foundation scope: this client establishes the BSD-socket connection on a
// background thread, frames + sends + receives bytes, and surfaces a
// `start()` entry point that performs the Ed25519 challenge-response
// handshake. No actual filter decisions are exchanged yet; that surface
// lands in Alpha-2.
//

import Foundation
import Darwin

/// Errors emitted by the IPC client.
public enum IPCClientError: Error, Equatable {
    case alreadyStarted
    case notStarted
    case transportClosed
    case connectFailed(String)
    case framingError(String)
    case envelopeMalformed(String)
    case handshakeTimeout
    case handshakeRejected(String)
    case socketPathTooLong(maxBytes: Int, actual: Int)
    case sendFailed(String)
    case sendBeforeHandshake
}

/// Configuration knobs.
public struct IPCClientOptions {
    public let path: String
    public let handshakeTimeoutSeconds: TimeInterval

    public init(path: String, handshakeTimeoutSeconds: TimeInterval = 5.0) {
        self.path = path
        self.handshakeTimeoutSeconds = handshakeTimeoutSeconds
    }
}

/// Post-handshake inbound message listener. The dispatcher registers a
/// callback via `setMessageListener` so it can route `manifest_updated`
/// notifications + future `decision_response` envelopes into application
/// state. Callbacks are invoked on the client's internal queue; the
/// dispatcher is responsible for hopping to its own queue if needed.
public typealias IPCMessageListener = (IpcMessage) -> Void

/// Alpha-3 (this build) extends Alpha-1's connect-and-handshake surface
/// with post-handshake send + receive routing. Inbound frames after the
/// handshake completes are decoded into `IpcMessage` and forwarded to the
/// registered listener; the dispatcher (`ExtensionDispatcher`) handles
/// `manifest_updated` and emits `flow_decision_recorded` /
/// `flow_pending_approval` outbound.
///
/// The decision-response round-trip surface (operator approve / deny
/// for uncertain flows) is reserved for the Alpha-4 install scope; the
/// listener surface accepts the envelope today so the dispatcher can
/// route it once that lands.
public final class IPCClient {
    private let options: IPCClientOptions
    private let pinnedPublicKey: Data
    private var socketFD: Int32 = -1
    private var inbound = Data()
    private let queue: DispatchQueue
    private var receiveSource: DispatchSourceRead?
    private var handshakeContinuation: CheckedContinuation<HandshakeIdentity, Error>?
    private var handshakeIdentity: HandshakeIdentity?
    private var handshakeDeadline: DispatchSourceTimer?
    private var pendingChallengeNonce: Data?
    private var messageListener: IPCMessageListener?
    private var transportClosedListener: ((IPCClientError) -> Void)?
    private let socketConnector: (String) throws -> Int32
    /// Optional closure that re-resolves the daemon socket path on EVERY
    /// `start()`. The macOS daemon writes its authoritative socket path to the
    /// active-config file only once it is up; on a fresh boot the sysext starts
    /// first and would otherwise freeze a stale (home-default) path for the
    /// connection's lifetime, so the reconnect loop spins forever against a
    /// socket that never appears and audit telemetry never reaches the daemon
    /// (Finding B, A1 drill 2026-06-04). Re-resolving per attempt lets the
    /// reconnect loop converge on the daemon's real path once it appears. When
    /// nil, `options.path` is used (the legacy fixed-path behavior).
    private let pathResolver: (() -> String)?

    public init(
        options: IPCClientOptions,
        pinnedPublicKey: Data,
        pathResolver: (() -> String)? = nil
    ) {
        self.options = options
        self.pinnedPublicKey = pinnedPublicKey
        self.queue = DispatchQueue(label: "ai.sanctuaryprotocol.castle-wall.ipc-client")
        self.socketConnector = { path in
            try IPCClient.connectUDS(path: path)
        }
        self.pathResolver = pathResolver
    }

    init(
        options: IPCClientOptions,
        pinnedPublicKey: Data,
        socketConnector: @escaping (String) throws -> Int32,
        pathResolver: (() -> String)? = nil
    ) {
        self.options = options
        self.pinnedPublicKey = pinnedPublicKey
        self.queue = DispatchQueue(label: "ai.sanctuaryprotocol.castle-wall.ipc-client")
        self.socketConnector = socketConnector
        self.pathResolver = pathResolver
    }

    /// Raw Ed25519 public key bytes pinned for the fortress identity.
    /// The dispatcher also uses this key to verify signed manifest
    /// snapshots before the extension trusts IPC-delivered rules.
    public var pinnedPublicKeyBytes: Data {
        return pinnedPublicKey
    }

    /// Register a post-handshake inbound message listener. The callback
    /// fires for every decoded `IpcMessage` received AFTER the handshake
    /// completes (handshake frames are consumed internally). Idempotent;
    /// passing `nil` removes the listener. Thread-safe (synced on the
    /// client's internal queue).
    public func setMessageListener(_ listener: IPCMessageListener?) {
        queue.async {
            self.messageListener = listener
        }
    }

    /// Register a callback invoked when a previously-connected transport
    /// drops after handshake completion.
    public func setTransportClosedListener(_ listener: ((IPCClientError) -> Void)?) {
        queue.async {
            self.transportClosedListener = listener
        }
    }

    /// Send an arbitrary `IpcMessage` over the connection. The message is
    /// JSON-RPC-wrapped using the canonical method name derived from the
    /// `IpcMessage` discriminator, framed per LSP, and written on the
    /// internal queue. Returns immediately; failures surface to the
    /// optional `onError` callback rather than throwing synchronously
    /// (the IPC bridge is fire-and-forget for notifications).
    ///
    /// Requires the handshake to have completed. Sending before handshake
    /// returns `.sendBeforeHandshake` via `onError`.
    public func send(
        _ message: IpcMessage,
        onError: ((IPCClientError) -> Void)? = nil
    ) {
        queue.async {
            guard self.handshakeIdentity != nil else {
                onError?(.sendBeforeHandshake)
                return
            }
            guard self.socketFD >= 0 else {
                onError?(.transportClosed)
                return
            }
            let method = IPCClient.methodSuffix(for: message)
            let envelope = MessageEnvelope(
                jsonrpc: "2.0",
                method: "\(CastleWallConstants.ipcNamespace).\(method)",
                params: message
            )
            do {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.withoutEscapingSlashes]
                let bodyBytes = try encoder.encode(envelope)
                guard let bodyString = String(data: bodyBytes, encoding: .utf8) else {
                    onError?(.sendFailed("envelope body is not valid utf-8"))
                    return
                }
                let frameBytes = Framing.frame(bodyString)
                let written = frameBytes.withUnsafeBytes { ptr -> Int in
                    guard let base = ptr.baseAddress else { return -1 }
                    return Darwin.send(self.socketFD, base, frameBytes.count, 0)
                }
                if written < 0 {
                    onError?(.sendFailed("send() errno=\(errno)"))
                    return
                }
                if written != frameBytes.count {
                    onError?(.sendFailed("short write: \(written) of \(frameBytes.count) bytes"))
                    return
                }
            } catch {
                onError?(.sendFailed("\(error)"))
            }
        }
    }

    /// Map an `IpcMessage` to its JSON-RPC method suffix (the bit after
    /// the namespace). Mirrors the discriminator strings in
    /// `Messages.swift`.
    private static func methodSuffix(for message: IpcMessage) -> String {
        switch message {
        case .statusRequest: return "status_request"
        case .statusResponse: return "status_response"
        case .policyReloadRequest: return "policy_reload_request"
        case .policyReloadResponse: return "policy_reload_response"
        case .decisionRequest: return "decision_request"
        case .decisionResponse: return "decision_response"
        case .auditEmit: return "audit_emit"
        case .auditEmitMetricBatch: return "audit_emit_metric_batch"
        case .auditDrainRequest: return "audit_drain_request"
        case .auditDrainResponse: return "audit_drain_response"
        case .auditDrainAck: return "audit_drain_ack"
        case .unlockNotification: return "unlock_notification"
        case .lockNotification: return "lock_notification"
        case .handshakeChallenge: return "handshake_challenge"
        case .handshakeResponse: return "handshake_response"
        case .manifestSubscribe: return "manifest_subscribe"
        case .manifestUpdated: return "manifest_updated"
        case .armLease: return "arm_lease"
        case .flowDecisionRecorded: return "flow_decision_recorded"
        case .flowPendingApproval: return "flow_pending_approval"
        }
    }

    /// Open the UDS connection and perform the Ed25519 challenge-response
    /// handshake. Resolves with the verified peer identity on success.
    public func start() async throws -> HandshakeIdentity {
        guard socketFD == -1 else {
            throw IPCClientError.alreadyStarted
        }

        // Re-resolve the socket path on every attempt so a reconnect after the
        // daemon (re)starts converges on its newly-published path instead of a
        // path frozen at first bootstrap (Finding B).
        let bootstrapPath = options.path
        let path = pathResolver?() ?? bootstrapPath
        if path != bootstrapPath {
            CastleWallLog.lifecycle.notice(
                "ipc start re-resolved socket path: \(path) (bootstrap path was \(bootstrapPath))"
            )
        }
        let fd = try socketConnector(path)
        socketFD = fd

        return try await withCheckedThrowingContinuation { continuation in
            self.queue.async {
                self.handshakeContinuation = continuation
                self.startHandshakeDeadline()
                self.startReceiving(fd: fd)
                CastleWallLog.lifecycle.info("ipc connection ready; awaiting challenge")
            }
        }
    }

    /// Close the connection and reject any in-flight handshake.
    public func close() {
        queue.async {
            let continuation = self.handshakeContinuation
            self.handshakeContinuation = nil
            self.resetConnectionState()
            if let continuation {
                continuation.resume(throwing: IPCClientError.transportClosed)
            }
        }
    }

    // MARK: - Internals

    private static func connectUDS(path: String) throws -> Int32 {
        let pathBytes = Array(path.utf8)
        // sockaddr_un.sun_path is 104 bytes on Darwin.
        let maxPathLen = 104
        guard pathBytes.count + 1 <= maxPathLen else {
            CastleWallLog.lifecycle.error(
                "ipc socket path too long; path_length=\(pathBytes.count) max=\(maxPathLen - 1)"
            )
            throw IPCClientError.socketPathTooLong(maxBytes: maxPathLen - 1, actual: pathBytes.count)
        }

        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw IPCClientError.connectFailed("socket() failed: errno=\(errno)")
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        // Copy bytes into sun_path. sun_path is a tuple of CChar; bind it to a buffer pointer.
        withUnsafeMutableBytes(of: &addr.sun_path) { rawBuffer in
            for (i, byte) in pathBytes.enumerated() {
                rawBuffer[i] = byte
            }
            rawBuffer[pathBytes.count] = 0
        }
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)

        let connectResult = withUnsafePointer(to: &addr) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                Darwin.connect(fd, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connectResult == 0 else {
            let savedErrno = errno
            _ = Darwin.close(fd)
            throw IPCClientError.connectFailed("connect() failed: errno=\(savedErrno)")
        }

        // Set O_NONBLOCK so receive integrates with DispatchSource.
        let flags = Darwin.fcntl(fd, F_GETFL, 0)
        _ = Darwin.fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        return fd
    }

    private func startHandshakeDeadline() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + options.handshakeTimeoutSeconds)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            CastleWallLog.lifecycle.error("ipc handshake timed out")
            self.failHandshake(IPCClientError.handshakeTimeout)
        }
        timer.resume()
        handshakeDeadline = timer
    }

    private func cancelHandshakeDeadline() {
        handshakeDeadline?.cancel()
        handshakeDeadline = nil
    }

    private func startReceiving(fd: Int32) {
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        source.setEventHandler { [weak self] in
            guard let self else { return }
            self.drainSocket(fd: fd)
        }
        source.setCancelHandler { [fd] in
            _ = Darwin.close(fd)
        }
        source.resume()
        receiveSource = source
    }

    private func drainSocket(fd: Int32) {
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = buffer.withUnsafeMutableBufferPointer { ptr -> Int in
                guard let base = ptr.baseAddress else { return -1 }
                return Darwin.recv(fd, base, ptr.count, 0)
            }
            if n > 0 {
                inbound.append(contentsOf: buffer.prefix(n))
                drainFrames()
                continue
            }
            if n == 0 {
                CastleWallLog.lifecycle.notice("ipc peer closed")
                failHandshake(IPCClientError.transportClosed)
                return
            }
            // n < 0
            let e = errno
            if e == EAGAIN || e == EWOULDBLOCK {
                return
            }
            if e == EINTR {
                continue
            }
            CastleWallLog.lifecycle.error("ipc recv error: errno=\(e)")
            failHandshake(IPCClientError.transportClosed)
            return
        }
    }

    private func drainFrames() {
        while !inbound.isEmpty {
            let step = Framing.parseFrame(inbound)
            switch step {
            case .complete(let body, let consumed):
                inbound.removeSubrange(0..<consumed)
                handleFrame(body)
            case .needMore:
                return
            case .error(let reason):
                failHandshake(IPCClientError.framingError(reason))
                return
            }
        }
    }

    private func handleFrame(_ body: String) {
        guard let bodyData = body.data(using: .utf8) else {
            failHandshake(IPCClientError.envelopeMalformed("non-utf8 frame body"))
            return
        }
        let envelope: MessageEnvelope
        do {
            envelope = try JSONDecoder().decode(MessageEnvelope.self, from: bodyData)
        } catch {
            failHandshake(IPCClientError.envelopeMalformed("\(error)"))
            return
        }

        switch envelope.params {
        case .handshakeChallenge(let nonceB64url):
            handleHandshakeChallenge(nonceB64url: nonceB64url)
        case .handshakeResponse:
            handleHandshakeResponse(envelope.params)
        default:
            // Post-handshake routing. Before the handshake completes,
            // any non-challenge frame is a protocol error and rejected.
            if handshakeIdentity == nil {
                CastleWallLog.ipc.notice(
                    "received non-handshake frame before handshake complete; dropping"
                )
                return
            }
            if let listener = messageListener {
                listener(envelope.params)
            } else {
                CastleWallLog.ipc.notice(
                    "received post-handshake frame with no listener registered; dropping"
                )
            }
        }
    }

    private func handleHandshakeChallenge(nonceB64url: String) {
        guard handshakeIdentity == nil else {
            CastleWallLog.auth.notice("duplicate handshake challenge after authentication; dropping")
            return
        }
        do {
            let nonce = try Base64URL.decode(nonceB64url)
            guard nonce.count == CastleWallConstants.challengeNonceBytes else {
                failHandshake(IPCClientError.handshakeRejected(
                    "invalid challenge nonce length: expected \(CastleWallConstants.challengeNonceBytes), got \(nonce.count)"
                ))
                return
            }
            pendingChallengeNonce = nonce
            CastleWallLog.auth.info("handshake challenge received; awaiting signed response")
        } catch {
            failHandshake(IPCClientError.handshakeRejected("invalid challenge nonce: \(error)"))
        }
    }

    private func handleHandshakeResponse(_ response: IpcMessage) {
        guard handshakeIdentity == nil else {
            CastleWallLog.auth.notice("duplicate handshake response after authentication; dropping")
            return
        }
        guard let nonce = pendingChallengeNonce else {
            failHandshake(IPCClientError.handshakeRejected("handshake response before challenge"))
            return
        }
        do {
            let identity = try Auth.verifyHandshakeResponse(
                response,
                expectedNonce: nonce,
                pinnedPublicKey: pinnedPublicKey
            )
            pendingChallengeNonce = nil
            completeHandshake(identity)
        } catch {
            failHandshake(IPCClientError.handshakeRejected("invalid handshake response: \(error)"))
        }
    }

    private func completeHandshake(_ identity: HandshakeIdentity) {
        cancelHandshakeDeadline()
        handshakeIdentity = identity
        CastleWallLog.auth.notice(
            "handshake complete; fortress=\(identity.fortressId) signingKeyId=\(identity.signingKeyId)"
        )
        if let cont = handshakeContinuation {
            handshakeContinuation = nil
            cont.resume(returning: identity)
        }
    }

    private func failHandshake(_ error: Error) {
        let normalizedError = normalizeError(error)
        logHandshakeFailure(normalizedError)
        let continuation = handshakeContinuation
        let hadAuthenticatedSession = handshakeIdentity != nil
        handshakeContinuation = nil
        resetConnectionState()
        if let continuation {
            continuation.resume(throwing: normalizedError)
            return
        }
        if hadAuthenticatedSession {
            transportClosedListener?(normalizedError)
        }
    }

    private func resetConnectionState() {
        cancelHandshakeDeadline()
        pendingChallengeNonce = nil
        handshakeIdentity = nil
        inbound.removeAll(keepingCapacity: false)
        let source = receiveSource
        receiveSource = nil
        if let source {
            source.cancel()
        } else if socketFD != -1 {
            _ = Darwin.close(socketFD)
        }
        socketFD = -1
    }

    private func normalizeError(_ error: Error) -> IPCClientError {
        if let ipcError = error as? IPCClientError {
            return ipcError
        }
        return .sendFailed(String(describing: error))
    }

    private func logHandshakeFailure(_ error: IPCClientError) {
        switch error {
        case .alreadyStarted:
            CastleWallLog.auth.error("handshake failed: alreadyStarted")
        case .notStarted:
            CastleWallLog.auth.error("handshake failed: notStarted")
        case .transportClosed:
            CastleWallLog.auth.error("handshake failed: transportClosed")
        case .connectFailed(let reason):
            CastleWallLog.auth.error("handshake failed: connectFailed reason=\(reason)")
        case .framingError(let reason):
            CastleWallLog.auth.error("handshake failed: framingError reason=\(reason)")
        case .envelopeMalformed(let reason):
            CastleWallLog.auth.error("handshake failed: envelopeMalformed reason=\(reason)")
        case .handshakeTimeout:
            CastleWallLog.auth.error("handshake failed: handshakeTimeout")
        case .handshakeRejected(let reason):
            CastleWallLog.auth.error("handshake failed: handshakeRejected reason=\(reason)")
        case .socketPathTooLong(let maxBytes, let actual):
            CastleWallLog.auth.error(
                "handshake failed: socketPathTooLong actual=\(actual) max=\(maxBytes)"
            )
        case .sendFailed(let reason):
            CastleWallLog.auth.error("handshake failed: sendFailed reason=\(reason)")
        case .sendBeforeHandshake:
            CastleWallLog.auth.error("handshake failed: sendBeforeHandshake")
        }
    }

}
