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

/// Foundation-scope client: opens the UDS connection, performs the
/// handshake, then idles. Subsequent builds extend with status-request,
/// policy-reload, decision-request, and audit-emit flows.
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

    public init(options: IPCClientOptions, pinnedPublicKey: Data) {
        self.options = options
        self.pinnedPublicKey = pinnedPublicKey
        self.queue = DispatchQueue(label: "ai.sanctuaryprotocol.castle-wall.ipc-client")
    }

    /// Open the UDS connection and perform the Ed25519 challenge-response
    /// handshake. Resolves with the verified peer identity on success.
    public func start() async throws -> HandshakeIdentity {
        guard socketFD == -1 else {
            throw IPCClientError.alreadyStarted
        }

        let fd = try connectUDS(path: options.path)
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
            self.cancelHandshakeDeadline()
            self.receiveSource?.cancel()
            self.receiveSource = nil
            if self.socketFD != -1 {
                _ = Darwin.close(self.socketFD)
                self.socketFD = -1
            }
            if let cont = self.handshakeContinuation {
                self.handshakeContinuation = nil
                cont.resume(throwing: IPCClientError.transportClosed)
            }
        }
    }

    // MARK: - Internals

    private func connectUDS(path: String) throws -> Int32 {
        let pathBytes = Array(path.utf8)
        // sockaddr_un.sun_path is 104 bytes on Darwin.
        let maxPathLen = 104
        guard pathBytes.count + 1 <= maxPathLen else {
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
        source.setCancelHandler {
            // Real fd close is owned by `close()`.
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
        default:
            CastleWallLog.ipc.notice("dropping non-handshake frame in foundation scope")
        }
    }

    private func handleHandshakeChallenge(nonceB64url: String) {
        // Foundation scope: this client is the *extension* side, which
        // verifies a counterparty signature. The current foundation build
        // only RECEIVES the challenge; signing happens on the Sanctuary
        // main side. We surface the nonce up to the lifecycle layer for
        // future builds to wire the verifier path. For now we treat the
        // arrival of a valid challenge as the handshake-complete signal.
        do {
            let nonce = try Base64URL.decode(nonceB64url)
            pendingChallengeNonce = nonce
            CastleWallLog.auth.info("handshake challenge received; awaiting paired response in Alpha-2")
        } catch {
            failHandshake(IPCClientError.handshakeRejected("invalid challenge nonce: \(error)"))
            return
        }

        // Foundation: signal completion now. Alpha-2 will replace this with
        // a true response-verification round-trip.
        let identity = HandshakeIdentity(
            fortressId: "<pending Alpha-2>",
            signingKeyId: "<pending Alpha-2>"
        )
        completeHandshake(identity)
    }

    private func completeHandshake(_ identity: HandshakeIdentity) {
        cancelHandshakeDeadline()
        handshakeIdentity = identity
        if let cont = handshakeContinuation {
            handshakeContinuation = nil
            cont.resume(returning: identity)
        }
    }

    private func failHandshake(_ error: Error) {
        cancelHandshakeDeadline()
        if let cont = handshakeContinuation {
            handshakeContinuation = nil
            cont.resume(throwing: error)
        }
    }
}
