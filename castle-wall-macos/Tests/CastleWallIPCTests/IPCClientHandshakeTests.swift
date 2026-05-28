//
// IPCClientHandshakeTests.swift
//
// Live UDS handshake tests for the macOS extension-side IPC client.
//

import XCTest
import CryptoKit
import Darwin
@testable import CastleWallIPC

final class IPCClientHandshakeTests: XCTestCase {
    func testUnsignedPeerCannotDeliverManifestBeforeAuthentication() async throws {
        let signing = Curve25519.Signing.PrivateKey()
        let server = try RogueUDSServer { fd in
            let nonce = Data(repeating: 0x41, count: CastleWallConstants.challengeNonceBytes)
            try Self.sendMessage(.handshakeChallenge(nonceB64url: Base64URL.encode(nonce)), to: fd)
            try Self.sendMessage(Self.manifestUpdated(signature: "rogue-unsigned"), to: fd)
            Darwin.usleep(500_000)
        }
        defer { server.stop() }

        let client = try server.makeClient(
            pinnedPublicKey: signing.publicKey.rawRepresentation,
            handshakeTimeoutSeconds: 0.2
        )
        var receivedManifest = false
        client.setMessageListener { message in
            if case .manifestUpdated = message {
                receivedManifest = true
            }
        }
        defer { client.close() }

        do {
            _ = try await client.start()
            XCTFail("unsigned peer must not complete handshake")
        } catch IPCClientError.handshakeTimeout {
            // expected
        } catch IPCClientError.transportClosed {
            // Also fail-closed: the unauthenticated peer disconnected
            // before the handshake deadline fired.
        } catch {
            XCTFail("expected handshakeTimeout or transportClosed, got \(error)")
        }
        XCTAssertFalse(receivedManifest)
    }

    func testWronglySignedPeerCannotDeliverManifestBeforeAuthentication() async throws {
        let pinned = Curve25519.Signing.PrivateKey()
        let attacker = Curve25519.Signing.PrivateKey()
        let server = try RogueUDSServer { fd in
            let nonce = Data(repeating: 0x42, count: CastleWallConstants.challengeNonceBytes)
            try Self.sendMessage(.handshakeChallenge(nonceB64url: Base64URL.encode(nonce)), to: fd)
            let signature = try attacker.signature(for: nonce)
            try Self.sendMessage(.handshakeResponse(HandshakeResponseBody(
                fortressId: "attacker",
                signingKeyId: "wrong-key",
                nonceSignatureB64url: Base64URL.encode(signature)
            )), to: fd)
            try Self.sendMessage(Self.manifestUpdated(signature: "rogue-wrong-key"), to: fd)
        }
        defer { server.stop() }

        let client = try server.makeClient(
            pinnedPublicKey: pinned.publicKey.rawRepresentation,
            handshakeTimeoutSeconds: 1.0
        )
        var receivedManifest = false
        client.setMessageListener { message in
            if case .manifestUpdated = message {
                receivedManifest = true
            }
        }
        defer { client.close() }

        do {
            _ = try await client.start()
            XCTFail("wrong-key peer must not complete handshake")
        } catch IPCClientError.handshakeRejected(let reason) {
            XCTAssertTrue(reason.contains("signatureMismatch"), reason)
        } catch {
            XCTFail("expected handshakeRejected, got \(error)")
        }
        XCTAssertFalse(receivedManifest)
    }

    func testPinnedPeerCanAuthenticateAndDeliverManifest() async throws {
        let signing = Curve25519.Signing.PrivateKey()
        let server = try RogueUDSServer { fd in
            let nonce = Data(repeating: 0x43, count: CastleWallConstants.challengeNonceBytes)
            try Self.sendMessage(.handshakeChallenge(nonceB64url: Base64URL.encode(nonce)), to: fd)
            let signature = try signing.signature(for: nonce)
            try Self.sendMessage(.handshakeResponse(HandshakeResponseBody(
                fortressId: "fortress-1",
                signingKeyId: "identity-v1",
                nonceSignatureB64url: Base64URL.encode(signature)
            )), to: fd)
            try Self.sendMessage(Self.manifestUpdated(signature: "trusted"), to: fd)
        }
        defer { server.stop() }

        let client = try server.makeClient(
            pinnedPublicKey: signing.publicKey.rawRepresentation,
            handshakeTimeoutSeconds: 1.0
        )
        let manifestReceived = expectation(description: "manifest delivered after authentication")
        client.setMessageListener { message in
            if case .manifestUpdated(let body) = message, body.manifestSignatureB64url == "trusted" {
                manifestReceived.fulfill()
            }
        }
        defer { client.close() }

        let identity = try await client.start()
        XCTAssertEqual(identity.fortressId, "fortress-1")
        XCTAssertEqual(identity.signingKeyId, "identity-v1")
        await fulfillment(of: [manifestReceived], timeout: 1.0)
    }

    private static func manifestUpdated(signature: String) -> IpcMessage {
        return .manifestUpdated(ManifestUpdatedBody(
            manifestSignatureB64url: signature,
            rules: []
        ))
    }

    private static func sendMessage(_ message: IpcMessage, to fd: Int32) throws {
        let envelope = MessageEnvelope(
            jsonrpc: "2.0",
            method: "\(CastleWallConstants.ipcNamespace).\(methodSuffix(for: message))",
            params: message
        )
        let encoded = try JSONEncoder().encode(envelope)
        let body = String(decoding: encoded, as: UTF8.self)
        let bytes = Framing.frame(body)
        try bytes.withUnsafeBytes { ptr in
            guard let base = ptr.baseAddress else { return }
            var written = 0
            while written < bytes.count {
                let n = Darwin.send(fd, base.advanced(by: written), bytes.count - written, 0)
                guard n > 0 else {
                    throw POSIXError(.EPIPE)
                }
                written += n
            }
        }
    }

    private static func methodSuffix(for message: IpcMessage) -> String {
        switch message {
        case .handshakeChallenge: return "handshake_challenge"
        case .handshakeResponse: return "handshake_response"
        case .manifestUpdated: return "manifest_updated"
        default: return "test_message"
        }
    }
}

private final class RogueUDSServer {
    let path: String
    private var clientFD: Int32
    private let queue = DispatchQueue(label: "ai.sanctuaryprotocol.castle-wall.rogue-uds-test")

    init(handler: @escaping (Int32) throws -> Void) throws {
        self.path = "socketpair://cw-ipc-\(UUID().uuidString)"
        var fds = [Int32](repeating: -1, count: 2)
        guard Darwin.socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        self.clientFD = fds[0]
        let serverFD = fds[1]
        queue.async {
            defer { _ = Darwin.close(serverFD) }
            do {
                try handler(serverFD)
            } catch {
                XCTFail("rogue UDS server failed: \(error)")
            }
        }
    }

    func makeClient(
        pinnedPublicKey: Data,
        handshakeTimeoutSeconds: TimeInterval
    ) throws -> IPCClient {
        guard clientFD >= 0 else {
            throw IPCClientError.transportClosed
        }
        let fd = clientFD
        clientFD = -1
        return IPCClient(
            options: IPCClientOptions(path: path, handshakeTimeoutSeconds: handshakeTimeoutSeconds),
            pinnedPublicKey: pinnedPublicKey,
            socketConnector: { _ in fd }
        )
    }

    func stop() {
        if clientFD >= 0 {
            _ = Darwin.close(clientFD)
            clientFD = -1
        }
    }

    deinit {
        stop()
    }
}
