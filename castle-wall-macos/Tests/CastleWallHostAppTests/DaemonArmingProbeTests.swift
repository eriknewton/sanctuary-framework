import XCTest
import CastleWallIPC
@testable import CastleWallHostApp

final class DaemonArmingProbeTests: XCTestCase {
    enum ProbeError: Error {
        case failedPinLoad
        case failedHandshake
    }

    final class FakeClient: DaemonHandshakeClient {
        let shouldSucceed: Bool
        private(set) var closed = false

        init(shouldSucceed: Bool) {
            self.shouldSucceed = shouldSucceed
        }

        func start() async throws -> HandshakeIdentity {
            guard shouldSucceed else {
                throw ProbeError.failedHandshake
            }
            return HandshakeIdentity(fortressId: "fortress", signingKeyId: "key")
        }

        func close() {
            closed = true
        }
    }

    func testAuthenticatedProbeAcceptsActiveConfigWithValidHandshake() async {
        let pinnedKey = Data(repeating: 7, count: 32)
        let client = FakeClient(shouldSucceed: true)

        let ready = await DaemonArmingProbe.authenticatedDaemonPresent(
            pinnedPublicKeyPath: "/pin",
            resolveSocketPath: {
                "/tmp/castle.sock"
            },
            loadPinnedPublicKey: { url in
                XCTAssertEqual(url.path, "/pin")
                return pinnedKey
            },
            makeClient: { path, key in
                XCTAssertEqual(path, "/tmp/castle.sock")
                XCTAssertEqual(key, pinnedKey)
                return client
            }
        )

        XCTAssertTrue(ready)
        XCTAssertTrue(client.closed)
    }

    func testAuthenticatedProbeRejectsUnauthenticatedListener() async {
        let client = FakeClient(shouldSucceed: false)

        let ready = await DaemonArmingProbe.authenticatedDaemonPresent(
            resolveSocketPath: {
                "/tmp/castle.sock"
            },
            loadPinnedPublicKey: { _ in Data(repeating: 7, count: 32) },
            makeClient: { _, _ in client }
        )

        XCTAssertFalse(ready)
        XCTAssertTrue(client.closed)
    }

    func testAuthenticatedProbeRejectsFallbackPathWithoutActiveConfig() async {
        var madeClient = false

        let ready = await DaemonArmingProbe.authenticatedDaemonPresent(
            resolveSocketPath: {
                nil
            },
            loadPinnedPublicKey: { _ in
                XCTFail("pin should not load when arming-ready socket is absent")
                throw ProbeError.failedPinLoad
            },
            makeClient: { _, _ in
                madeClient = true
                return FakeClient(shouldSucceed: true)
            }
        )

        XCTAssertFalse(ready)
        XCTAssertFalse(madeClient)
    }
}
