//
// ArmLeaseTests.swift
//
// Pins the daemon->extension TTL-expiry "0-contract" that the #885 fix depends
// on. The Node daemon anchors an absolute operator TTL deadline and its
// heartbeat re-broadcasts the REMAINING seconds; on expiry it broadcasts
// `ttl_seconds: 0`. The Swift extension MUST treat a received zero as
// "expire now" so `failOpenReason() == "ttl_expired"` and the flow engine
// fails OPEN for positively classified OPERATOR traffic only
// (`fail_open_deadman`, brick-prevention/recovery); agent and unattributed
// traffic fails CLOSED during a stale lease (`fail_closed_deadman_agent`,
// AR-1). The TS half of that
// contract has deterministic coverage; before this suite the Swift half was
// verified only by inspection. These tests lock the wire decode (`ttl_seconds`
// present-zero, not nil) and the ArmLease expiry semantics with an injected
// clock so no real sleeps are needed.
//

import XCTest
@testable import CastleWallFilter
@testable import CastleWallIPC

final class ArmLeaseTests: XCTestCase {

    // A controllable clock so the fail-open deadline is asserted without a
    // wall-clock sleep. `advance` moves the ArmLease's notion of "now" forward.
    private final class TestClock {
        private var current: Date
        init(_ start: Date = Date(timeIntervalSince1970: 1_700_000_000)) {
            self.current = start
        }
        func now() -> Date { current }
        func advance(_ seconds: TimeInterval) { current = current.addingTimeInterval(seconds) }
    }

    private func makeLease(_ clock: TestClock) -> ArmLease {
        return ArmLease(now: clock.now)
    }

    private func armUpdate(ttlSeconds: UInt32?, heartbeat: UInt32 = 5) -> ArmLeaseUpdate {
        return ArmLeaseUpdate(
            armed: true,
            revoked: false,
            ttlSeconds: ttlSeconds,
            heartbeatIntervalSeconds: heartbeat
        )
    }

    func test_defaultLeaseReportsMissingUntilFirstArmLeaseArrives() {
        let clock = TestClock()
        let lease = makeLease(clock)

        XCTAssertEqual(lease.missingLeaseReason(), "arm_lease_missing")
        XCTAssertFalse(lease.snapshot().leaseReceived)

        lease.update(armUpdate(ttlSeconds: nil))

        XCTAssertNil(lease.missingLeaseReason())
        XCTAssertTrue(lease.snapshot().leaseReceived)

        lease.resetToMissing()

        XCTAssertEqual(lease.missingLeaseReason(), "arm_lease_missing")
        XCTAssertFalse(lease.snapshot().leaseReceived)
        XCTAssertFalse(lease.snapshot().armed)
        XCTAssertFalse(lease.snapshot().revoked)
    }

    // MARK: - The 0-contract: ttl_seconds == 0 means "expire now"

    // This is the exact instant the daemon broadcasts on expiry. A received
    // zero must fail open immediately, not be treated as absent/durable.
    func test_ttlZero_failsOpenImmediately_ttlExpired() {
        let clock = TestClock()
        let lease = makeLease(clock)

        lease.update(armUpdate(ttlSeconds: 0))

        XCTAssertEqual(
            lease.failOpenReason(),
            "ttl_expired",
            "a received ttl_seconds:0 (the daemon's expiry broadcast) must expire the lease NOW"
        )
    }

    // MARK: - Durable / --no-ttl never fires

    func test_ttlNil_isDurable_neverExpiresOnTtl() {
        let clock = TestClock()
        let lease = makeLease(clock)

        lease.update(armUpdate(ttlSeconds: nil))
        XCTAssertNil(lease.failOpenReason(), "a --no-ttl (nil) arm must never trip ttl_expired")

        // Even far in the future the TTL deadline never fires (the heartbeat
        // deadline is a separate concern, kept alive here at 2x interval).
        clock.advance(3600)
        XCTAssertNotEqual(
            lease.failOpenReason(),
            "ttl_expired",
            "durable arming must not report ttl_expired regardless of elapsed time"
        )
    }

    // MARK: - Positive TTL: live now, expired after the deadline passes

    func test_positiveTtl_liveBeforeDeadline_expiredAfter() {
        let clock = TestClock()
        let lease = makeLease(clock)

        // Heartbeat interval is sized so its deadline (2x interval) stays beyond
        // the TTL window under test. In live operation the daemon re-broadcasts a
        // fresh heartbeat every ~5s, continually pushing heartbeatExpiresAt out;
        // this single-update test simulates that "heartbeat always fresh" state so
        // the assertion isolates the TTL (dead-man) deadline, not heartbeat_stopped.
        lease.update(armUpdate(ttlSeconds: 90, heartbeat: 3600))
        XCTAssertNil(lease.failOpenReason(), "a fresh 90s lease must be live immediately after arming")

        // Just before the deadline: still enforcing (anti-spurious-disarm: a
        // dead-man must never fire early on a live lease).
        clock.advance(89)
        XCTAssertNil(lease.failOpenReason(), "at t+89s of a 90s lease the wall must still enforce")

        // At/after the deadline: fail open on ttl_expired.
        clock.advance(1)
        XCTAssertEqual(
            lease.failOpenReason(),
            "ttl_expired",
            "at t+90s of a 90s lease the dead-man must fire ttl_expired"
        )
    }

    // MARK: - Re-arm replaces the deadline (does NOT stack)

    // The daemon's onArmLease adopts the MOST RECENT operator arm as
    // authoritative. A re-arm mid-lease must move the deadline to now+newTtl,
    // not extend or stack onto the prior one.
    func test_reArmMidLease_replacesDeadline_notStacked() {
        let clock = TestClock()
        let lease = makeLease(clock)

        // Large heartbeat interval keeps heartbeatExpiresAt beyond both TTL
        // windows so this test isolates the TTL deadline (see the note in
        // test_positiveTtl_liveBeforeDeadline_expiredAfter).
        lease.update(armUpdate(ttlSeconds: 90, heartbeat: 3600))
        clock.advance(60) // 30s remaining on the original lease

        // Re-arm with a fresh 30s TTL. New deadline is now+30 == original+90.
        lease.update(armUpdate(ttlSeconds: 30, heartbeat: 3600))
        XCTAssertNil(lease.failOpenReason(), "immediately after a re-arm the lease is live again")

        clock.advance(29)
        XCTAssertNil(lease.failOpenReason(), "the re-armed 30s deadline governs, not the stale original")

        clock.advance(1)
        XCTAssertEqual(
            lease.failOpenReason(),
            "ttl_expired",
            "the re-armed deadline fires at now+30s of the re-arm, proving replace-not-stack"
        )
    }

    // A fresh --no-ttl arm AFTER a positive-TTL arm returns to durable: the
    // prior TTL deadline is cleared and never fires.
    func test_reArmNoTtl_afterPositiveTtl_clearsDeadline() {
        let clock = TestClock()
        let lease = makeLease(clock)

        lease.update(armUpdate(ttlSeconds: 30))
        lease.update(armUpdate(ttlSeconds: nil)) // operator re-arms --no-ttl

        clock.advance(120)
        XCTAssertNotEqual(
            lease.failOpenReason(),
            "ttl_expired",
            "re-arming --no-ttl must clear the prior TTL deadline (resume durable)"
        )
    }

    // MARK: - Revoke clears the deadline

    func test_revoke_reportsLeaseRevoked_notTtlExpired() {
        let clock = TestClock()
        let lease = makeLease(clock)

        lease.update(armUpdate(ttlSeconds: 90))
        lease.update(ArmLeaseUpdate(
            armed: false,
            revoked: true,
            ttlSeconds: nil,
            heartbeatIntervalSeconds: 5
        ))

        XCTAssertEqual(lease.failOpenReason(), "lease_revoked", "an explicit revoke reports lease_revoked")

        // Advancing past the old deadline must not resurrect a stale ttl_expired.
        clock.advance(120)
        XCTAssertEqual(
            lease.failOpenReason(),
            "lease_revoked",
            "a revoked lease must not report a stale ttl_expired after the old deadline passes"
        )
    }

    // MARK: - Wire contract: JSON ttl_seconds:0 decodes to present-zero (not nil)

    // The daemon serializes an expiry lease with `ttl_seconds: 0`. If Swift
    // decoded that to nil (absent/durable) the dead-man would silently never
    // fire. Pin present-zero so a future decoder refactor cannot regress it.
    func test_wireDecode_ttlSecondsZero_isPresentZero_notNil() throws {
        let json = """
        {"type":"arm_lease","armed":true,"revoked":false,"ttl_seconds":0,"heartbeat_interval_seconds":5,"updated_at":"2026-07-05T00:00:00.000Z"}
        """.data(using: .utf8)!

        let body = try JSONDecoder().decode(ArmLeaseBody.self, from: json)
        XCTAssertEqual(body.ttlSeconds, 0, "ttl_seconds:0 must decode to a present zero, not nil")
        XCTAssertNotNil(body.ttlSeconds, "a zero TTL must not collapse to the durable (nil) case on the wire")
    }

    // Absent ttl_seconds (a genuine --no-ttl / durable lease) decodes to nil,
    // the complement of the zero case above.
    func test_wireDecode_ttlSecondsAbsent_isNil() throws {
        let json = """
        {"type":"arm_lease","armed":true,"revoked":false,"heartbeat_interval_seconds":5,"updated_at":"2026-07-05T00:00:00.000Z"}
        """.data(using: .utf8)!

        let body = try JSONDecoder().decode(ArmLeaseBody.self, from: json)
        XCTAssertNil(body.ttlSeconds, "an absent ttl_seconds is durable arming and must decode to nil")
    }

    // End-to-end wire->engine seam: a decoded zero-TTL body, applied via the
    // same ArmLeaseUpdate the dispatcher builds, expires the lease now.
    func test_wireZero_appliedToLease_expiresNow() throws {
        let json = """
        {"type":"arm_lease","armed":true,"revoked":false,"ttl_seconds":0,"heartbeat_interval_seconds":5,"updated_at":"2026-07-05T00:00:00.000Z"}
        """.data(using: .utf8)!
        let body = try JSONDecoder().decode(ArmLeaseBody.self, from: json)

        let clock = TestClock()
        let lease = makeLease(clock)
        lease.update(ArmLeaseUpdate(
            armed: body.armed,
            revoked: body.revoked,
            ttlSeconds: body.ttlSeconds,
            heartbeatIntervalSeconds: body.heartbeatIntervalSeconds
        ))

        XCTAssertEqual(
            lease.failOpenReason(),
            "ttl_expired",
            "a wire ttl_seconds:0 carried through ArmLeaseUpdate must fail open on ttl_expired"
        )
    }
}
