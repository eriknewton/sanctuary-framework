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
}
