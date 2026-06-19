import XCTest
@testable import CastleWallHostApp

/// Covers binary resolution (Finding C, A1 drill 2026-06-04): the host app must
/// locate the `sanctuary` CLI even when launched from Finder/`open` (no login
/// shell PATH), and must reject untrusted candidates.
final class SanctuaryServerBridgeTests: XCTestCase {

    // MARK: - Candidate selection (pure)

    func testResolvePicksFirstValidCandidate() {
        let chosen = SanctuaryServerBridge.resolveSanctuaryBinary(
            candidates: ["/a/sanctuary", "/b/sanctuary", "/c/sanctuary"],
            isValidBinary: { $0 == "/b/sanctuary" || $0 == "/c/sanctuary" }
        )
        XCTAssertEqual(chosen, "/b/sanctuary")
    }

    func testResolveRespectsPriorityOrder() {
        let chosen = SanctuaryServerBridge.resolveSanctuaryBinary(
            candidates: ["/first/sanctuary", "/second/sanctuary"],
            isValidBinary: { _ in true }
        )
        XCTAssertEqual(chosen, "/first/sanctuary")
    }

    func testResolveReturnsNilWhenNoCandidateValid() {
        let chosen = SanctuaryServerBridge.resolveSanctuaryBinary(
            candidates: ["/a/sanctuary", "/b/sanctuary"],
            isValidBinary: { _ in false }
        )
        XCTAssertNil(chosen)
    }

    func testResolveReturnsNilForEmptyCandidates() {
        let chosen = SanctuaryServerBridge.resolveSanctuaryBinary(
            candidates: [],
            isValidBinary: { _ in true }
        )
        XCTAssertNil(chosen)
    }

    // MARK: - Ownership validation (real filesystem)

    func testOwnerTrustedExecutableAcceptsRootOwnedFile() {
        // /bin/sh exists and is root-owned on every macOS.
        XCTAssertTrue(SanctuaryServerBridge.isOwnerTrustedExecutable("/bin/sh"))
    }

    func testOwnerTrustedExecutableRejectsMissingPath() {
        let missing = "/nonexistent/sanctuary-\(UUID().uuidString)"
        XCTAssertFalse(SanctuaryServerBridge.isOwnerTrustedExecutable(missing))
    }

    func testOwnerTrustedExecutableRejectsDirectory() {
        XCTAssertFalse(SanctuaryServerBridge.isOwnerTrustedExecutable("/usr/bin"))
    }

    // MARK: - Candidate list shape

    func testCandidatePathsIncludeCommonInstallDirs() {
        let candidates = SanctuaryServerBridge.candidateSanctuaryPaths()
        XCTAssertTrue(candidates.contains("/opt/homebrew/bin/sanctuary"))
        XCTAssertTrue(candidates.contains("/usr/local/bin/sanctuary"))
        XCTAssertTrue(candidates.contains { $0.hasSuffix("/.npm-global/bin/sanctuary") })
    }

    // MARK: - Sovereignty Posture dashboard handoff (native-to-web seam)

    func testDashboardPostureURLIsLoopbackPostureSurface() {
        let url = SanctuaryServerBridge.dashboardPostureURL(port: 3501)
        XCTAssertEqual(url.absoluteString, "http://127.0.0.1:3501/posture")
        XCTAssertEqual(url.scheme, "http")
        XCTAssertEqual(url.host, "127.0.0.1")
        XCTAssertEqual(url.port, 3501)
        XCTAssertEqual(url.path, "/posture")
    }

    func testDashboardPostureURLNeverCarriesAuthToken() {
        // Option 1 contract: loopback auto-auth covers the read-only posture
        // surface; a token in the URL would leak to history/referer. The page
        // reads `#token=` from the hash, so the handoff URL must carry neither a
        // fragment nor a query.
        let url = SanctuaryServerBridge.dashboardPostureURL(port: 3501)
        XCTAssertNil(url.fragment, "posture handoff URL must not populate #token=")
        XCTAssertNil(url.query, "posture handoff URL must not carry a query token")
        XCTAssertFalse(url.absoluteString.lowercased().contains("token"))
    }
}
