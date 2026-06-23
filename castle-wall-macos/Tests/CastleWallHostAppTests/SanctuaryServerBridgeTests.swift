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

    // MARK: - Wall arm-state decode (Piece B: single source of truth, fail-closed)

    func testArmStateDecodesArmed() {
        XCTAssertEqual(SanctuaryServerBridge.WallArmState(serverValue: "armed"), .armed)
    }

    func testArmStateDecodesNonGreenStates() {
        XCTAssertEqual(SanctuaryServerBridge.WallArmState(serverValue: "degraded"), .degraded)
        XCTAssertEqual(SanctuaryServerBridge.WallArmState(serverValue: "unknown"), .unknown)
        XCTAssertEqual(SanctuaryServerBridge.WallArmState(serverValue: "not_installed"), .notInstalled)
    }

    func testArmStateFailsClosedToUnknownOnUnrecognizedValue() {
        // Never decode an unexpected/garbage value into the green `.armed` state.
        XCTAssertEqual(SanctuaryServerBridge.WallArmState(serverValue: "ARMED"), .unknown)
        XCTAssertEqual(SanctuaryServerBridge.WallArmState(serverValue: "enabled"), .unknown)
        XCTAssertEqual(SanctuaryServerBridge.WallArmState(serverValue: ""), .unknown)
    }

    func testArmStateFailsClosedToUnknownOnMissingValue() {
        XCTAssertEqual(SanctuaryServerBridge.WallArmState(serverValue: nil), .unknown)
    }

    func testDecodeArmStateExtractsFieldFromPostureJSON() {
        let json = Data("""
        {"origin_machine":"m1","arm_state":"armed","platform":"macos"}
        """.utf8)
        XCTAssertEqual(SanctuaryServerBridge.decodeArmState(from: json), "armed")
    }

    func testDecodeArmStateReturnsNilWhenFieldAbsent() {
        let json = Data("""
        {"origin_machine":"m1","platform":"macos"}
        """.utf8)
        XCTAssertNil(SanctuaryServerBridge.decodeArmState(from: json))
    }

    func testDecodeArmStateReturnsNilOnMalformedJSON() {
        XCTAssertNil(SanctuaryServerBridge.decodeArmState(from: Data("not json".utf8)))
    }

    // The full pipeline: a malformed payload must NOT yield a green badge.
    func testMalformedPostureNeverYieldsArmed() {
        let decoded = SanctuaryServerBridge.decodeArmState(from: Data("not json".utf8))
        XCTAssertNotEqual(SanctuaryServerBridge.WallArmState(serverValue: decoded), .armed)
    }

    // MARK: - Producer authenticity decode (honest tooltip basis, fail-closed)

    func testProducerAuthenticityDecodesKnownBases() {
        XCTAssertEqual(
            SanctuaryServerBridge.ProducerAuthenticity(serverValue: "producer_signed"),
            .producerSigned
        )
        XCTAssertEqual(
            SanctuaryServerBridge.ProducerAuthenticity(serverValue: "channel_authenticated"),
            .channelAuthenticated
        )
        XCTAssertEqual(
            SanctuaryServerBridge.ProducerAuthenticity(serverValue: "not_applicable"),
            .notApplicable
        )
    }

    // An unknown/garbage/missing basis must NEVER decode into a producer-signed
    // OVERCLAIM: it falls closed to `.notApplicable` so the tooltip won't claim a
    // signature the server didn't assert (matches the macOS channel-auth floor).
    func testProducerAuthenticityFailsClosedToNotApplicable() {
        XCTAssertEqual(
            SanctuaryServerBridge.ProducerAuthenticity(serverValue: "PRODUCER_SIGNED"),
            .notApplicable
        )
        XCTAssertEqual(
            SanctuaryServerBridge.ProducerAuthenticity(serverValue: "signed"),
            .notApplicable
        )
        XCTAssertEqual(
            SanctuaryServerBridge.ProducerAuthenticity(serverValue: ""),
            .notApplicable
        )
        XCTAssertEqual(
            SanctuaryServerBridge.ProducerAuthenticity(serverValue: nil),
            .notApplicable
        )
    }

    func testDecodeProducerAuthenticityExtractsFieldFromPostureJSON() {
        let json = Data("""
        {"arm_state":"armed","producer_authenticity":"channel_authenticated"}
        """.utf8)
        XCTAssertEqual(
            SanctuaryServerBridge.decodeProducerAuthenticity(from: json),
            "channel_authenticated"
        )
    }

    func testDecodeProducerAuthenticityReturnsNilWhenFieldAbsent() {
        let json = Data("""
        {"arm_state":"armed"}
        """.utf8)
        XCTAssertNil(SanctuaryServerBridge.decodeProducerAuthenticity(from: json))
    }

    func testDecodeProducerAuthenticityReturnsNilOnMalformedJSON() {
        XCTAssertNil(
            SanctuaryServerBridge.decodeProducerAuthenticity(from: Data("not json".utf8))
        )
    }

    // MARK: - Server-status transition hysteresis
    //
    // A single transient health-probe failure must NOT flip a previously
    // `.reachable` server to `.unreachable`: that teardown rebuilds the embedded
    // PostureWebView from the home URL and snaps the operator's in-board
    // navigation back to home. `nextServerStatus` absorbs one blip and only
    // declares `.unreachable` after `threshold` consecutive failures, while a
    // reachable probe recovers immediately.

    func testReachableProbeIsAuthoritativeImmediatelyAndResetsFailures() {
        let t = SanctuaryServerBridge.nextServerStatus(
            current: .unreachable,
            probeReachable: true,
            consecutiveFailures: 5,
            threshold: 2
        )
        XCTAssertEqual(t.status, .reachable)
        XCTAssertEqual(t.consecutiveFailures, 0)
    }

    func testSingleFailureFromReachableHoldsReachable() {
        // The exact regression: one blip while reachable must NOT tear down the
        // embedded board. Status stays `.reachable`; the failure is counted.
        let t = SanctuaryServerBridge.nextServerStatus(
            current: .reachable,
            probeReachable: false,
            consecutiveFailures: 0,
            threshold: 2
        )
        XCTAssertEqual(t.status, .reachable)
        XCTAssertEqual(t.consecutiveFailures, 1)
    }

    func testSecondConsecutiveFailureFromReachableFlipsUnreachable() {
        let t = SanctuaryServerBridge.nextServerStatus(
            current: .reachable,
            probeReachable: false,
            consecutiveFailures: 1,
            threshold: 2
        )
        XCTAssertEqual(t.status, .unreachable)
        XCTAssertEqual(t.consecutiveFailures, 2)
    }

    func testReachableProbeRecoversFromUnreachable() {
        // Recovery is never delayed by hysteresis.
        let t = SanctuaryServerBridge.nextServerStatus(
            current: .unreachable,
            probeReachable: true,
            consecutiveFailures: 3,
            threshold: 2
        )
        XCTAssertEqual(t.status, .reachable)
        XCTAssertEqual(t.consecutiveFailures, 0)
    }

    func testColdStartSingleFailureStaysUnknownNotReachable() {
        // Cold start (`.unknown`): a single failure must NOT prematurely declare
        // `.reachable` (which would mount the web view onto a connection-refused
        // page) — it holds `.unknown` until the threshold is met.
        let t = SanctuaryServerBridge.nextServerStatus(
            current: .unknown,
            probeReachable: false,
            consecutiveFailures: 0,
            threshold: 2
        )
        XCTAssertEqual(t.status, .unknown)
        XCTAssertEqual(t.consecutiveFailures, 1)
    }

    func testColdStartReachesUnreachableAfterThresholdFailures() {
        let t = SanctuaryServerBridge.nextServerStatus(
            current: .unknown,
            probeReachable: false,
            consecutiveFailures: 1,
            threshold: 2
        )
        XCTAssertEqual(t.status, .unreachable)
        XCTAssertEqual(t.consecutiveFailures, 2)
    }

    func testThresholdOfOneFlipsImmediately() {
        // A threshold of 1 disables hysteresis: a single failure flips at once.
        let t = SanctuaryServerBridge.nextServerStatus(
            current: .reachable,
            probeReachable: false,
            consecutiveFailures: 0,
            threshold: 1
        )
        XCTAssertEqual(t.status, .unreachable)
        XCTAssertEqual(t.consecutiveFailures, 1)
    }

    func testThresholdIsClampedToAtLeastOne() {
        // A nonsensical threshold (<= 0) must still terminate: clamp to 1 so a
        // failure can never be ignored forever.
        let t = SanctuaryServerBridge.nextServerStatus(
            current: .reachable,
            probeReachable: false,
            consecutiveFailures: 0,
            threshold: 0
        )
        XCTAssertEqual(t.status, .unreachable)
        XCTAssertEqual(t.consecutiveFailures, 1)
    }

    func testConfiguredThresholdAbsorbsAtLeastOneBlip() {
        // Lock the shipped threshold: it must be >= 2 so a single blip is always
        // absorbed (the whole point of the hysteresis).
        XCTAssertGreaterThanOrEqual(SanctuaryServerBridge.unreachableHysteresisThreshold, 2)
    }

    // MARK: - Posture surface state (Slice 1a: the three honest states)
    //
    // The operator-facing surface is one of three honest states (design §3.1):
    //   .live          reachable -> embedded board
    //   .reconnecting  WAS reachable, now failing inside the recovery budget ->
    //                  dimmed, timestamped last-known frame + "reconnecting"
    //   .unreachable   cold start (no last-known frame) OR down past the budget
    //                  -> native down-screen
    // The honesty invariant under test: `.reconnecting` is reachable ONLY when we
    // actually have a last-known frame to dim, and only inside the bounded budget.

    func testReachableSurfaceIsLive() {
        let s = SanctuaryServerBridge.postureSurfaceState(
            status: .reachable,
            consecutiveFailures: 0,
            hasLastKnownPosture: true,
            recoveryBudget: 6
        )
        XCTAssertEqual(s, .live)
    }

    func testReachableSurfaceIsLiveEvenWithoutPriorPosture() {
        // First successful probe: reachable is always live regardless of history.
        let s = SanctuaryServerBridge.postureSurfaceState(
            status: .reachable,
            consecutiveFailures: 0,
            hasLastKnownPosture: false,
            recoveryBudget: 6
        )
        XCTAssertEqual(s, .live)
    }

    func testWasReachableNowFailingInsideBudgetIsReconnecting() {
        // The new state: we have a last-known frame and are inside the budget ->
        // show the dimmed reconnecting frame, NOT the dead screen.
        let s = SanctuaryServerBridge.postureSurfaceState(
            status: .unreachable,
            consecutiveFailures: 2,
            hasLastKnownPosture: true,
            recoveryBudget: 6
        )
        XCTAssertEqual(s, .reconnecting)
    }

    func testReconnectingHoldsUpToButNotIncludingBudget() {
        // Just below the budget still reconnects.
        let justBelow = SanctuaryServerBridge.postureSurfaceState(
            status: .unreachable,
            consecutiveFailures: 5,
            hasLastKnownPosture: true,
            recoveryBudget: 6
        )
        XCTAssertEqual(justBelow, .reconnecting)
    }

    func testFailingPastBudgetFallsToUnreachable() {
        // At/over the budget, the honest "reconnecting" promise expires -> the
        // native down-screen. Recovery was given a fair window and did not come.
        let atBudget = SanctuaryServerBridge.postureSurfaceState(
            status: .unreachable,
            consecutiveFailures: 6,
            hasLastKnownPosture: true,
            recoveryBudget: 6
        )
        XCTAssertEqual(atBudget, .unreachable)

        let overBudget = SanctuaryServerBridge.postureSurfaceState(
            status: .unreachable,
            consecutiveFailures: 9,
            hasLastKnownPosture: true,
            recoveryBudget: 6
        )
        XCTAssertEqual(overBudget, .unreachable)
    }

    func testColdStartNeverReachableIsUnreachableNotReconnecting() {
        // Cold start honesty (design §3.2): with no last-known frame we NEVER
        // fabricate a stale "reconnecting" view, even inside the budget window.
        let coldUnreachable = SanctuaryServerBridge.postureSurfaceState(
            status: .unreachable,
            consecutiveFailures: 1,
            hasLastKnownPosture: false,
            recoveryBudget: 6
        )
        XCTAssertEqual(coldUnreachable, .unreachable)

        // Even `.unknown` (cold start, below hysteresis) with no posture maps to
        // the unreachable surface (the caller renders the native empty-state).
        let coldUnknown = SanctuaryServerBridge.postureSurfaceState(
            status: .unknown,
            consecutiveFailures: 0,
            hasLastKnownPosture: false,
            recoveryBudget: 6
        )
        XCTAssertEqual(coldUnknown, .unreachable)
    }

    func testRecoveryBudgetIsClampedToAtLeastOne() {
        // A nonsensical budget (<= 0) must not make every failed probe
        // "reconnecting forever": clamp to 1 so a single failure past it falls to
        // the down-screen.
        let s = SanctuaryServerBridge.postureSurfaceState(
            status: .unreachable,
            consecutiveFailures: 1,
            hasLastKnownPosture: true,
            recoveryBudget: 0
        )
        XCTAssertEqual(s, .unreachable)
    }

    func testConfiguredRecoveryBudgetExceedsHysteresisThreshold() {
        // Lock the shipped relationship: the recovery budget must be strictly
        // greater than the hysteresis threshold, otherwise the Reconnecting state
        // could never appear (the surface would flip straight to the down-screen
        // the same probe it became `.unreachable`).
        XCTAssertGreaterThan(
            SanctuaryServerBridge.recoveryBudgetFailures,
            SanctuaryServerBridge.unreachableHysteresisThreshold
        )
    }

    // MARK: - Stale-timestamp copy (Slice 1a Fix 2: do not understate staleness)
    //
    // The Reconnecting banner and the down-screen both stamp the last-reachable
    // moment so the operator knows how old the dimmed frame is. A bare HH:mm:ss
    // would read an overnight or multi-day outage as if it were seconds old; the
    // formatted string must therefore include the DATE, not just the time-of-day.

    func testStaleTimestampIncludesTheDateNotJustTime() {
        // Pin a known instant well in the past (2026-01-15). The formatted copy
        // must contain a date component, so a frame stamped today vs. weeks ago is
        // visibly different to the operator (honesty across time).
        var comps = DateComponents()
        comps.year = 2026
        comps.month = 1
        comps.day = 15
        comps.hour = 14
        comps.minute = 13
        comps.second = 7
        let cal = Calendar.current
        let date = cal.date(from: comps)!

        let formatted = ContentView.staleTimestamp(date)

        // The day-of-month and the year must both be present (a pure HH:mm:ss
        // string would contain neither). This is the regression guard: if the
        // formatter is ever narrowed back to time-only, this fails.
        XCTAssertTrue(formatted.contains("15"), "stale timestamp must include the day: \(formatted)")
        XCTAssertTrue(formatted.contains("2026"), "stale timestamp must include the year: \(formatted)")
    }

    func testStaleTimestampDistinguishesDifferentDaysAtSameClockTime() {
        // Two frames captured at the same wall-clock time on different days must
        // produce DIFFERENT copy. A time-only formatter would collapse them to the
        // same string and understate a day-old frame as if it were current.
        let cal = Calendar.current
        func at(year: Int, month: Int, day: Int) -> Date {
            var c = DateComponents()
            c.year = year; c.month = month; c.day = day
            c.hour = 9; c.minute = 0; c.second = 0
            return cal.date(from: c)!
        }
        let today = at(year: 2026, month: 6, day: 22)
        let weeksAgo = at(year: 2026, month: 6, day: 1)

        XCTAssertNotEqual(
            ContentView.staleTimestamp(today),
            ContentView.staleTimestamp(weeksAgo),
            "same clock time on different days must format differently so staleness is not understated"
        )
    }
}
