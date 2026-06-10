//
// SocketPathTests.swift
//
// Mirror of `server/test/castle-wall/runtime/socket-path.test.ts`. Each
// fixture below MUST resolve to the same `path` string the TS helper
// returns. If you add a fixture here, add the corresponding case to the
// TS test in the same PR.
//

import Darwin
import XCTest
@testable import CastleWallIPC

final class SocketPathTests: XCTestCase {
    private var tempFiles: [String] = []

    override func tearDown() {
        for file in tempFiles {
            try? FileManager.default.removeItem(atPath: file)
        }
        tempFiles.removeAll()
        super.tearDown()
    }

    private func writeActiveConfig(_ contents: String) throws -> String {
        let path = "\(NSTemporaryDirectory())socket-path-\(UUID().uuidString).json"
        try contents.write(toFile: path, atomically: true, encoding: .utf8)
        tempFiles.append(path)
        return path
    }

    func testActiveConfigTakesPrecedenceOverExplicitOverrideOnMacOS() throws {
        let configPath = try writeActiveConfig("""
        {"socket_path":"/tmp/from-active-config.sock","fortress_id":"fortress-test","pid":\(getpid()),"started_at":"2026-05-25T00:00:00.000Z"}
        """)
        let out = SocketPath.resolve(
            platform: "darwin",
            explicitOverride: "/tmp/from-env.sock",
            activeConfigPath: configPath
        )
        XCTAssertEqual(out.path, "/tmp/from-active-config.sock")
        XCTAssertEqual(out.source, .macosActiveConfig)
    }

    func testActiveConfigFallsThroughWhenAbsent() {
        let out = SocketPath.resolve(
            platform: "darwin",
            homeDir: "/Users/op",
            activeConfigPath: "\(NSTemporaryDirectory())missing-\(UUID().uuidString).json"
        )
        XCTAssertEqual(out.path, "/Users/op/.sanctuary/castle.sock")
        XCTAssertEqual(out.source, .macosHomeDefault)
    }

    func testMalformedActiveConfigFallsThrough() throws {
        let configPath = try writeActiveConfig("{bad-json")
        let out = SocketPath.resolve(
            platform: "darwin",
            homeDir: "/Users/op",
            activeConfigPath: configPath
        )
        XCTAssertEqual(out.path, "/Users/op/.sanctuary/castle.sock")
        XCTAssertEqual(out.source, .macosHomeDefault)
    }

    func testActiveConfigWithoutPidFallsThrough() throws {
        let configPath = try writeActiveConfig("""
        {"socket_path":"/tmp/no-pid.sock","fortress_id":"fortress-test","started_at":"2026-05-25T00:00:00.000Z"}
        """)
        let out = SocketPath.resolve(
            platform: "darwin",
            homeDir: "/Users/op",
            activeConfigPath: configPath
        )
        XCTAssertEqual(out.path, "/Users/op/.sanctuary/castle.sock")
        XCTAssertEqual(out.source, .macosHomeDefault)
    }

    func testActiveConfigWithDeadPidFallsThrough() throws {
        let configPath = try writeActiveConfig("""
        {"socket_path":"/tmp/stale.sock","fortress_id":"fortress-test","pid":999999,"started_at":"2026-05-25T00:00:00.000Z"}
        """)
        let out = SocketPath.resolve(
            platform: "darwin",
            homeDir: "/Users/op",
            activeConfigPath: configPath
        )
        XCTAssertEqual(out.path, "/Users/op/.sanctuary/castle.sock")
        XCTAssertEqual(out.source, .macosHomeDefault)
    }

    // MARK: - activeDaemonPresent (F-UX-2 arm gate probe)

    /// The arm gate's "daemon up with policy" signal: an active-config naming
    /// a live pid. (Local-only probe — `activeDaemonPresent` has no TS mirror;
    /// the resolve fixtures above stay the cross-language parity set.)
    func testActiveDaemonPresentWithLivePid() throws {
        let configPath = try writeActiveConfig("""
        {"socket_path":"/tmp/live.sock","fortress_id":"fortress-test","pid":\(getpid()),"started_at":"2026-05-25T00:00:00.000Z"}
        """)
        XCTAssertTrue(SocketPath.activeDaemonPresent(activeConfigPath: configPath))
    }

    /// A stale active-config (dead pid) must read as daemon-down — arming on a
    /// leftover discovery file would fail-close the machine (the B2 lesson).
    func testActiveDaemonAbsentWithDeadPid() throws {
        let configPath = try writeActiveConfig("""
        {"socket_path":"/tmp/stale.sock","fortress_id":"fortress-test","pid":999999,"started_at":"2026-05-25T00:00:00.000Z"}
        """)
        XCTAssertFalse(SocketPath.activeDaemonPresent(activeConfigPath: configPath))
    }

    func testActiveDaemonAbsentWhenFileMissing() {
        XCTAssertFalse(
            SocketPath.activeDaemonPresent(
                activeConfigPath: "\(NSTemporaryDirectory())missing-\(UUID().uuidString).json"
            )
        )
    }

    func testActiveDaemonAbsentWhenConfigMalformedOrPidless() throws {
        let malformed = try writeActiveConfig("{bad-json")
        XCTAssertFalse(SocketPath.activeDaemonPresent(activeConfigPath: malformed))

        let pidless = try writeActiveConfig("""
        {"socket_path":"/tmp/no-pid.sock","fortress_id":"fortress-test","started_at":"2026-05-25T00:00:00.000Z"}
        """)
        XCTAssertFalse(SocketPath.activeDaemonPresent(activeConfigPath: pidless))
    }

    // MARK: - activeDaemonPresentForArming (codex P1: arm-grade, spoof-proof)

    /// Bind + listen a real unix socket at a short /tmp path (sun_path is 104
    /// bytes; NSTemporaryDirectory is too long on macOS). Closed + unlinked in
    /// teardown.
    private func makeListeningUnixSocket() throws -> String {
        let path = "/tmp/cw-arm-\(UUID().uuidString.prefix(8)).sock"
        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(fd, 0, "socket() failed: errno=\(errno)")
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            for (i, byte) in bytes.enumerated() { raw[i] = byte }
            raw[bytes.count] = 0
        }
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        unlink(path)
        let bound = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.bind(fd, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bound == 0, Darwin.listen(fd, 4) == 0 else {
            Darwin.close(fd)
            throw XCTSkip("could not bind/listen test unix socket: errno=\(errno)")
        }
        tempFiles.append(path)
        addTeardownBlock { Darwin.close(fd) }
        return path
    }

    private func armingConfig(socketPath: String, pid: Int32) -> String {
        """
        {"socket_path":"\(socketPath)","fortress_id":"fortress-test","pid":\(pid),"started_at":"2026-06-09T00:00:00.000Z"}
        """
    }

    /// THE P1 spoof: a forged active-config naming a live pid (the exact
    /// shape any local user can plant) must NOT satisfy arming — the real
    /// custody probe sees the test-owned (non-root) file and rejects it, even
    /// with a genuinely connectable socket behind it.
    func testForgedConfigWithLivePidDoesNotSatisfyArming() throws {
        let socketPath = try makeListeningUnixSocket()
        let configPath = try writeActiveConfig(
            armingConfig(socketPath: socketPath, pid: getpid())
        )
        XCTAssertFalse(
            SocketPath.activeDaemonPresentForArming(activeConfigPath: configPath)
        )
    }

    /// Structural no-legacy-fallback proof: plant a forged config at the REAL
    /// legacy /tmp path (the exact attack file), point the probe at a missing
    /// protected path, and hand it a custody probe + connect stub that would
    /// BOTH pass if the legacy file were consulted. Discovery-grade accepts
    /// this exact setup; arm-grade must not.
    func testArmingNeverConsultsLegacyTmpFallback() throws {
        let legacyPath = SocketPath.legacyActiveConfigPath
        let priorContents = FileManager.default.contents(atPath: legacyPath)
        addTeardownBlock {
            if let priorContents {
                FileManager.default.createFile(atPath: legacyPath, contents: priorContents)
            } else {
                try? FileManager.default.removeItem(atPath: legacyPath)
            }
        }
        let socketPath = try makeListeningUnixSocket()
        let forged = armingConfig(socketPath: socketPath, pid: getpid())
        do {
            try forged.write(toFile: legacyPath, atomically: true, encoding: .utf8)
        } catch {
            // Sticky /tmp: cannot replace a legacy file owned by another user
            // (e.g. a real root daemon's leftover). Hermetic assertions below
            // do not depend on the planted file, but skip to keep the test's
            // claim honest.
            throw XCTSkip("cannot plant forged legacy active-config: \(error)")
        }

        let missingProtected = "\(NSTemporaryDirectory())missing-\(UUID().uuidString).json"

        // Sanity: the discovery-grade probe DOES fall back to the forged
        // legacy file when given the production default path. (Skip the
        // assertion's spoof claim if a real protected config exists on this
        // box; the arm-grade assertions below are hermetic either way.)
        if !FileManager.default.fileExists(atPath: SocketPath.activeConfigPath) {
            XCTAssertTrue(SocketPath.activeDaemonPresent())
        }

        XCTAssertFalse(
            SocketPath.activeDaemonPresentForArming(
                activeConfigPath: missingProtected,
                custody: FileCustody(probe: FileCustody.rootSimulating()),
                isSymlink: { _ in false },
                canConnect: { _ in true }
            ),
            "arm-grade probe must have no legacy /tmp code path at all"
        )
    }

    /// Custody leg in isolation: with parse + connect stubs that pass, a
    /// non-root-owned active-config still rejects arming (the sysext's
    /// F-A2-4 gate, reused).
    func testArmingRejectsNonRootOwnedActiveConfig() throws {
        let configPath = try writeActiveConfig(
            armingConfig(socketPath: "/tmp/whatever.sock", pid: getpid())
        )
        XCTAssertFalse(
            SocketPath.activeDaemonPresentForArming(
                activeConfigPath: configPath,
                custody: FileCustody(), // real probe: test file is operator-owned
                isSymlink: { _ in false },
                canConnect: { _ in true }
            )
        )
    }

    /// A symlinked active-config must reject arming even when the ownership
    /// probe reads root (a link must not launder custody onto attacker
    /// content).
    func testArmingRejectsSymlinkedActiveConfig() throws {
        let socketPath = try makeListeningUnixSocket()
        let realConfig = try writeActiveConfig(
            armingConfig(socketPath: socketPath, pid: getpid())
        )
        let linkPath = "\(NSTemporaryDirectory())cw-arm-link-\(UUID().uuidString).json"
        try FileManager.default.createSymbolicLink(
            atPath: linkPath, withDestinationPath: realConfig
        )
        tempFiles.append(linkPath)
        XCTAssertFalse(
            SocketPath.activeDaemonPresentForArming(
                activeConfigPath: linkPath,
                custody: FileCustody(probe: FileCustody.rootSimulating())
            )
        )
    }

    /// Liveness leg: a config passing custody + parse whose named socket does
    /// not accept a connect (nothing listening) rejects arming. kill(pid,0)
    /// liveness would have passed here — the connect probe is the point.
    func testArmingRejectsUnconnectableSocket() throws {
        let deadSocket = "/tmp/cw-arm-dead-\(UUID().uuidString.prefix(8)).sock"
        let configPath = try writeActiveConfig(
            armingConfig(socketPath: deadSocket, pid: getpid())
        )
        XCTAssertFalse(
            SocketPath.activeDaemonPresentForArming(
                activeConfigPath: configPath,
                custody: FileCustody(probe: FileCustody.rootSimulating())
            )
        )
    }

    /// Genuine path: root-owned (simulated — CI is unprivileged) non-symlink
    /// config naming a live pid and a REAL listening unix socket is accepted,
    /// through the real connect probe.
    func testArmingAcceptsGenuineConfigWithConnectableSocket() throws {
        let socketPath = try makeListeningUnixSocket()
        let configPath = try writeActiveConfig(
            armingConfig(socketPath: socketPath, pid: getpid())
        )
        XCTAssertTrue(
            SocketPath.activeDaemonPresentForArming(
                activeConfigPath: configPath,
                custody: FileCustody(probe: FileCustody.rootSimulating())
            )
        )
    }

    /// Stale-config guard carries over from discovery: a dead pid rejects
    /// arming even with a connectable socket at the named path.
    func testArmingRejectsDeadPidEvenWithConnectableSocket() throws {
        let socketPath = try makeListeningUnixSocket()
        let configPath = try writeActiveConfig(
            armingConfig(socketPath: socketPath, pid: 999_999)
        )
        XCTAssertFalse(
            SocketPath.activeDaemonPresentForArming(
                activeConfigPath: configPath,
                custody: FileCustody(probe: FileCustody.rootSimulating())
            )
        )
    }

    /// The raw connect probe: true for a listening socket, false for a path
    /// with nothing behind it, false for an over-long path.
    func testCanConnectUnixSocketProbe() throws {
        let live = try makeListeningUnixSocket()
        XCTAssertTrue(SocketPath.canConnectUnixSocket(at: live))
        XCTAssertFalse(
            SocketPath.canConnectUnixSocket(
                at: "/tmp/cw-arm-nothing-\(UUID().uuidString.prefix(8)).sock"
            )
        )
        XCTAssertFalse(
            SocketPath.canConnectUnixSocket(at: "/tmp/\(String(repeating: "x", count: 120)).sock")
        )
    }

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
