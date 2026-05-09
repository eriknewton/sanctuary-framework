//
// SocketPathTests.swift
//
// Mirror of `server/test/castle-wall/runtime/socket-path.test.ts`. Each
// fixture below MUST resolve to the same `path` string the TS helper
// returns. If you add a fixture here, add the corresponding case to the
// TS test in the same PR.
//

import XCTest
@testable import CastleWallIPC

final class SocketPathTests: XCTestCase {
    func testExplicitOverrideTakesPrecedenceOverPlatform() {
        let out = SocketPath.resolve(
            platform: "linux",
            fortressId: "abc123",
            explicitOverride: "/tmp/custom.sock"
        )
        XCTAssertEqual(out.path, "/tmp/custom.sock")
        XCTAssertEqual(out.source, .explicitOverride)
    }

    func testLinuxPerFortressPath() {
        let out = SocketPath.resolve(platform: "linux", fortressId: "abc123")
        XCTAssertEqual(out.path, "/run/sanctuary/abc123/filter.sock")
        XCTAssertEqual(out.source, .linuxPerFortress)
    }

    func testLinuxDefaultsFortressIdWhenAbsent() {
        let out = SocketPath.resolve(platform: "linux")
        XCTAssertEqual(out.path, "/run/sanctuary/default/filter.sock")
        XCTAssertEqual(out.source, .linuxPerFortress)
    }

    func testMacOSFortressPath() {
        let out = SocketPath.resolve(
            platform: "darwin",
            fortressPath: "/Users/op/.sanctuary"
        )
        XCTAssertEqual(out.path, "/Users/op/.sanctuary/castle.sock")
        XCTAssertEqual(out.source, .macosPerFortress)
    }

    func testMacOSStripsTrailingSlash() {
        let out = SocketPath.resolve(
            platform: "darwin",
            fortressPath: "/Users/op/.sanctuary/"
        )
        XCTAssertEqual(out.path, "/Users/op/.sanctuary/castle.sock")
    }

    func testMacOSHomeDefault() {
        let out = SocketPath.resolve(platform: "darwin", homeDir: "/Users/op")
        XCTAssertEqual(out.path, "/Users/op/.sanctuary/castle.sock")
        XCTAssertEqual(out.source, .macosHomeDefault)
    }

    func testMacOSRootDaemonFallback() {
        let out = SocketPath.resolve(platform: "darwin")
        XCTAssertEqual(out.path, "/var/run/sanctuary-castle.sock")
        XCTAssertEqual(out.source, .macosRootDaemon)
    }

    func testEmptyOverridesFallThrough() {
        let out = SocketPath.resolve(
            platform: "darwin",
            fortressPath: "",
            homeDir: "/Users/op",
            explicitOverride: ""
        )
        XCTAssertEqual(out.path, "/Users/op/.sanctuary/castle.sock")
        XCTAssertEqual(out.source, .macosHomeDefault)
    }

    func testUnknownPlatformDegradesToMacOSDefaults() {
        let out = SocketPath.resolve(platform: "freebsd", homeDir: "/home/op")
        XCTAssertEqual(out.path, "/home/op/.sanctuary/castle.sock")
        XCTAssertEqual(out.source, .macosHomeDefault)
    }
}
