//
// ProtectionGateTests.swift
//
// F-UX-2: the manual Arm / Disarm gate matrices. Fail-closed both ways:
// arm requires helper-ready AND daemon-up-with-policy; disarm is
// unconditional; auto-arm respects the operator-disarm latch.
//

import XCTest
@testable import CastleWallHostApp

final class ProtectionGateTests: XCTestCase {

    // MARK: - canArm (fail-closed: both legs required)

    /// The B2 lesson: arming without a policy-bearing daemon fail-closes the
    /// machine to deny-all. Any missing leg must block arm.
    func testCanArmRequiresBothHelperAndDaemon() {
        XCTAssertTrue(ProtectionGate.canArm(helperReady: true, daemonUpWithPolicy: true))
        XCTAssertFalse(ProtectionGate.canArm(helperReady: true, daemonUpWithPolicy: false))
        XCTAssertFalse(ProtectionGate.canArm(helperReady: false, daemonUpWithPolicy: true))
        XCTAssertFalse(ProtectionGate.canArm(helperReady: false, daemonUpWithPolicy: false))
    }

    // MARK: - canDisarm (unconditional)

    /// Disarm must ALWAYS be available to the operator — the F-UX-2 drill had
    /// no in-app disarm at all (a System-Settings trip).
    func testDisarmIsAlwaysAvailable() {
        XCTAssertTrue(ProtectionGate.canDisarm())
    }

    // MARK: - shouldAutoArm (the operator-disarm latch makes Disarm real)

    func testAutoArmFiresOnlyWhenAllowedNotArmedNotLatched() {
        XCTAssertTrue(
            ProtectionGate.shouldAutoArm(canArm: true, alreadyArmed: false, operatorDisarmed: false)
        )
    }

    /// A manual disarm must stick: auto-arm re-evaluation runs every few
    /// seconds, so without the latch the Disarm button would be a no-op.
    func testAutoArmRespectsOperatorDisarmLatch() {
        XCTAssertFalse(
            ProtectionGate.shouldAutoArm(canArm: true, alreadyArmed: false, operatorDisarmed: true)
        )
    }

    func testAutoArmSkipsWhenAlreadyArmed() {
        XCTAssertFalse(
            ProtectionGate.shouldAutoArm(canArm: true, alreadyArmed: true, operatorDisarmed: false)
        )
    }

    func testAutoArmNeverFiresWhenGateBlocked() {
        XCTAssertFalse(
            ProtectionGate.shouldAutoArm(canArm: false, alreadyArmed: false, operatorDisarmed: false)
        )
        XCTAssertFalse(
            ProtectionGate.shouldAutoArm(canArm: false, alreadyArmed: true, operatorDisarmed: true)
        )
    }

    // MARK: - disarmControlVisible (codex P2: failed disarm keeps the exit path)

    /// The Disarm control must stay on screen while armed OR while the last
    /// disarm attempt is unverified — a failed saveToPreferences drops the
    /// filter state out of "armed" while the REAL filter may still be on, and
    /// that exact moment must not hide the retry.
    func testDisarmControlVisibleWheneverArmedOrDisarmUnverified() {
        XCTAssertTrue(ProtectionGate.disarmControlVisible(isArmed: true, disarmPending: false))
        XCTAssertTrue(ProtectionGate.disarmControlVisible(isArmed: true, disarmPending: true))
        XCTAssertTrue(ProtectionGate.disarmControlVisible(isArmed: false, disarmPending: true))
        XCTAssertFalse(ProtectionGate.disarmControlVisible(isArmed: false, disarmPending: false))
    }

    // MARK: - armBlockedReason (a blocked Arm is never silent)

    func testNoBlockedReasonWhenArmAllowed() {
        XCTAssertNil(ProtectionGate.armBlockedReason(helperReady: true, daemonUpWithPolicy: true))
    }

    func testBlockedReasonNamesTheMissingLeg() {
        let helperMissing = ProtectionGate.armBlockedReason(
            helperReady: false, daemonUpWithPolicy: true
        )
        XCTAssertNotNil(helperMissing)
        XCTAssertTrue(helperMissing!.lowercased().contains("helper"))

        let daemonMissing = ProtectionGate.armBlockedReason(
            helperReady: true, daemonUpWithPolicy: false
        )
        XCTAssertNotNil(daemonMissing)
        XCTAssertTrue(daemonMissing!.lowercased().contains("daemon"))

        let bothMissing = ProtectionGate.armBlockedReason(
            helperReady: false, daemonUpWithPolicy: false
        )
        XCTAssertNotNil(bothMissing)
        XCTAssertTrue(bothMissing!.lowercased().contains("helper"))
        XCTAssertTrue(bothMissing!.lowercased().contains("daemon"))
    }
}
