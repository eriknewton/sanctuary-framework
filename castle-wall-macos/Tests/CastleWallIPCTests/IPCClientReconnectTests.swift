//
// IPCClientReconnectTests.swift
//
// Finding B (A1 drill 2026-06-04): the sysext must re-resolve the daemon
// socket path on every (re)connect, so a reconnect after the daemon (re)starts
// converges on its newly-published path instead of one frozen at first
// bootstrap. On a fresh boot the sysext starts before the daemon, resolves the
// home-default fallback, and — without re-resolution — would dial that stale
// path forever, dropping all audit telemetry even though enforcement survives.
//

import XCTest
@testable import CastleWallIPC

final class IPCClientReconnectTests: XCTestCase {

    func testStartReResolvesSocketPathOnEachAttempt() async {
        var connectorPaths: [String] = []
        var resolvedPath = "/stale/home-default/castle.sock"
        let client = IPCClient(
            options: IPCClientOptions(path: "/bootstrap/frozen/castle.sock"),
            pinnedPublicKey: Data(repeating: 0, count: 32),
            socketConnector: { path in
                connectorPaths.append(path)
                throw IPCClientError.connectFailed("no listener at \(path)")
            },
            pathResolver: { resolvedPath }
        )

        // Fresh boot: resolver returns the home-default fallback; daemon not up.
        do {
            _ = try await client.start()
            XCTFail("connect should fail while no daemon is listening")
        } catch {
            // expected connectFailed
        }
        XCTAssertEqual(connectorPaths.last, "/stale/home-default/castle.sock")

        // Daemon comes up and publishes its real fortress path via active-config;
        // the resolver now returns it. The next reconnect must pick it up.
        resolvedPath = "/run/fortress-abc/castle.sock"
        do {
            _ = try await client.start()
            XCTFail("connect should fail (stub connector always throws)")
        } catch {
            // expected connectFailed
        }
        XCTAssertEqual(connectorPaths.last, "/run/fortress-abc/castle.sock")

        // The frozen bootstrap path is never dialed once a resolver is supplied.
        XCTAssertFalse(connectorPaths.contains("/bootstrap/frozen/castle.sock"))
    }

    func testStartFallsBackToOptionsPathWithoutResolver() async {
        var connectorPaths: [String] = []
        let client = IPCClient(
            options: IPCClientOptions(path: "/legacy/fixed/castle.sock"),
            pinnedPublicKey: Data(repeating: 0, count: 32),
            socketConnector: { path in
                connectorPaths.append(path)
                throw IPCClientError.connectFailed("stub")
            }
        )

        do {
            _ = try await client.start()
            XCTFail("stub connector always throws")
        } catch {
            // expected
        }
        XCTAssertEqual(connectorPaths, ["/legacy/fixed/castle.sock"])
    }
}
