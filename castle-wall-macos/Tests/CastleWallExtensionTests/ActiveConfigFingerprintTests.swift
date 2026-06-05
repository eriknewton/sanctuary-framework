//
// ActiveConfigFingerprintTests.swift
//
// Fix-round coverage for gauntlet finding F-A2-4: the sysext's active-config
// FINGERPRINT GATE must only consume a ROOT-OWNED protected config. A world-
// writable /tmp file (or any operator-owned file) must never be able to plant a
// live pid + bogus pinned_pubkey_sha256 and force a perpetual fingerprint-
// mismatch retry (a default-deny DoS that wedges bootstrap).
//
// These call the static, I/O-injectable helpers directly — no NEFilterProvider
// instance, no real filesystem ownership, no root.
//

import XCTest
@testable import CastleWallFilter
import CastleWallIPC

final class ActiveConfigFingerprintTests: XCTestCase {
    private let socketPath = "/Users/op/.sanctuary/castle.sock"
    private let configPath = "/Library/Application Support/Sanctuary/castle-active.json"

    private func validConfigData(socket: String, fingerprint: String) -> Data {
        let pid = Int(getpid()) // a definitely-live pid
        let json = """
        {"socket_path":"\(socket)","fortress_id":"fort-1","pid":\(pid),\
        "started_at":"2026-06-05T00:00:00Z","pinned_pubkey_sha256":"\(fingerprint)"}
        """
        return Data(json.utf8)
    }

    // MARK: - Owner gate (the F-A2-4 fix)

    func testIgnoresNonRootOwnedConfig() {
        // Operator-owned (uid 501) — i.e. the "/tmp-sourced" or daemon-written
        // file. Even though the bytes are well-formed with a live pid, the gate
        // must advertise NO fingerprint so it cannot force a refusal.
        let custody = FileCustody(probe: { _ in FileFacts(exists: true, uid: 501, mode: 0o644) })
        let result = CastleWallFilterProvider.activeConfigFingerprint(
            forSocketPath: socketPath,
            configPath: configPath,
            custody: custody,
            loadData: { _ in self.validConfigData(socket: self.socketPath, fingerprint: "abc123") },
            isPidAliveFn: { _ in true }
        )
        XCTAssertNil(result, "an operator-owned active-config must not drive the gate")
    }

    func testIgnoresAbsentConfig() {
        let custody = FileCustody(probe: { _ in FileFacts(exists: false, uid: -1, mode: 0) })
        let result = CastleWallFilterProvider.activeConfigFingerprint(
            forSocketPath: socketPath,
            configPath: configPath,
            custody: custody,
            loadData: { _ in nil },
            isPidAliveFn: { _ in true }
        )
        XCTAssertNil(result)
    }

    func testConsumesRootOwnedConfig() throws {
        // Root-owned protected config with matching socket + live pid: the gate
        // is honored and returns the advertised fingerprint (lowercased).
        let custody = FileCustody(probe: { _ in FileFacts(exists: true, uid: 0, mode: 0o644) })
        let result = CastleWallFilterProvider.activeConfigFingerprint(
            forSocketPath: socketPath,
            configPath: configPath,
            custody: custody,
            loadData: { path in
                XCTAssertEqual(path, self.configPath, "must read ONLY the protected path")
                return self.validConfigData(socket: self.socketPath, fingerprint: "ABCDEF")
            },
            isPidAliveFn: { _ in true }
        )
        let fp = try XCTUnwrap(result)
        XCTAssertEqual(fp.fortressId, "fort-1")
        XCTAssertEqual(fp.pinnedPubkeySha256, "abcdef")
    }

    func testDefaultConfigPathIsProtectedNotTmp() {
        // Guards against a regression that re-introduces the /tmp fallback as the
        // gate input: the default configPath must be the protected location.
        XCTAssertEqual(SocketPath.activeConfigPath, configPath)
        XCTAssertNotEqual(SocketPath.activeConfigPath, SocketPath.legacyActiveConfigPath)
    }

    // MARK: - Pure parse invariants

    func testParseRejectsSocketMismatch() {
        let result = CastleWallFilterProvider.parseActiveConfigFingerprint(
            data: validConfigData(socket: "/some/other.sock", fingerprint: "abc"),
            forSocketPath: socketPath,
            isPidAliveFn: { _ in true }
        )
        XCTAssertNil(result)
    }

    func testParseRejectsDeadPid() {
        let result = CastleWallFilterProvider.parseActiveConfigFingerprint(
            data: validConfigData(socket: socketPath, fingerprint: "abc"),
            forSocketPath: socketPath,
            isPidAliveFn: { _ in false }
        )
        XCTAssertNil(result)
    }

    func testParseRejectsEmptyFingerprint() {
        let result = CastleWallFilterProvider.parseActiveConfigFingerprint(
            data: validConfigData(socket: socketPath, fingerprint: ""),
            forSocketPath: socketPath,
            isPidAliveFn: { _ in true }
        )
        XCTAssertNil(result)
    }
}
