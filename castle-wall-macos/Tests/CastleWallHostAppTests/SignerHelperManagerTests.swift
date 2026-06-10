//
// SignerHelperManagerTests.swift
//
// Unit coverage for the pure parts of the signer-helper manager: SMAppService
// status mapping and the auto-arm precondition. The privileged register/approve
// path is console-only and not exercised here.
//

import XCTest
import ServiceManagement
@testable import CastleWallHostApp

final class SignerHelperManagerTests: XCTestCase {

    func testStatusMapping() {
        XCTAssertEqual(SignerHelperManager.map(.notRegistered), .notRegistered)
        XCTAssertEqual(SignerHelperManager.map(.enabled), .enabled)
        XCTAssertEqual(SignerHelperManager.map(.requiresApproval), .requiresApproval)
        XCTAssertEqual(SignerHelperManager.map(.notFound), .notFound)
    }

    func testShouldAutoArmRequiresBothHelperAndPin() {
        XCTAssertTrue(SignerHelperManager.shouldAutoArm(helperEnabled: true, pinPresent: true))
        XCTAssertFalse(SignerHelperManager.shouldAutoArm(helperEnabled: true, pinPresent: false))
        XCTAssertFalse(SignerHelperManager.shouldAutoArm(helperEnabled: false, pinPresent: true))
        XCTAssertFalse(SignerHelperManager.shouldAutoArm(helperEnabled: false, pinPresent: false))
    }

    func testPlistNameMatchesHelperIdentifier() {
        XCTAssertEqual(
            SignerHelperManager.plistName,
            "ai.sanctuaryprotocol.macos.castle-wall.signer-helper.plist"
        )
    }

    // MARK: - stateAfterRegister (FIX-1: benign first-run EPERM throw)

    /// The whole drill blocker: a daemon's first `register()` throws
    /// `SMAppServiceErrorDomain Code=1 "Operation not permitted"` while still
    /// landing the helper in BTM as `.requiresApproval`. The status wins — this
    /// must map to `.requiresApproval`, NOT `.error`.
    func testRegisterThrowsEPERMButStatusRequiresApprovalIsNotError() {
        let eperm = NSError(
            domain: "SMAppServiceErrorDomain",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: "Operation not permitted"]
        )
        XCTAssertEqual(
            SignerHelperManager.stateAfterRegister(error: eperm, status: .requiresApproval),
            .requiresApproval
        )
    }

    func testRegisterThrowsButStatusEnabledIsEnabled() {
        let eperm = NSError(domain: "SMAppServiceErrorDomain", code: 1)
        XCTAssertEqual(
            SignerHelperManager.stateAfterRegister(error: eperm, status: .enabled),
            .enabled
        )
    }

    /// A throw paired with a status that never advanced past `.notRegistered` is
    /// a genuine failure — surface it as `.error` with the thrown message.
    func testRegisterThrowsAndStatusNotRegisteredIsError() {
        let boom = NSError(
            domain: "SomeOtherDomain",
            code: 42,
            userInfo: [NSLocalizedDescriptionKey: "boom"]
        )
        XCTAssertEqual(
            SignerHelperManager.stateAfterRegister(error: boom, status: .notRegistered),
            .error("boom")
        )
    }

    func testRegisterNoThrowStatusNotRegisteredIsNotRegistered() {
        XCTAssertEqual(
            SignerHelperManager.stateAfterRegister(error: nil, status: .notRegistered),
            .notRegistered
        )
    }

    // MARK: - shouldKeepPolling (F-UX-1: post-register settle loop)

    /// The F-UX-1 race: immediately after `register()`, BTM may still report
    /// `.notRegistered` for a beat before flipping to `.requiresApproval`. The
    /// settle loop must keep polling through that window.
    func testKeepsPollingWhileNotRegisteredAndAttemptsRemain() {
        XCTAssertTrue(
            SignerHelperManager.shouldKeepPolling(status: .notRegistered, attempt: 0, maxAttempts: 10)
        )
        XCTAssertTrue(
            SignerHelperManager.shouldKeepPolling(status: .notRegistered, attempt: 9, maxAttempts: 10)
        )
        XCTAssertTrue(
            SignerHelperManager.shouldKeepPolling(status: .notFound, attempt: 0, maxAttempts: 10)
        )
    }

    /// `.requiresApproval` and `.enabled` are terminal — settle immediately so
    /// the approval banner renders without waiting out the poll budget.
    func testStopsPollingOnTerminalStatuses() {
        XCTAssertFalse(
            SignerHelperManager.shouldKeepPolling(status: .requiresApproval, attempt: 0, maxAttempts: 10)
        )
        XCTAssertFalse(
            SignerHelperManager.shouldKeepPolling(status: .enabled, attempt: 0, maxAttempts: 10)
        )
    }

    /// The poll budget is bounded: once attempts are exhausted the loop settles
    /// on whatever BTM reports (the UI then shows the retry affordance).
    func testStopsPollingWhenAttemptsExhausted() {
        XCTAssertFalse(
            SignerHelperManager.shouldKeepPolling(status: .notRegistered, attempt: 10, maxAttempts: 10)
        )
        XCTAssertFalse(
            SignerHelperManager.shouldKeepPolling(status: .notFound, attempt: 11, maxAttempts: 10)
        )
    }

    /// The poll budget covers a realistic BTM settle window (~3s) without
    /// being effectively unbounded.
    func testPollBudgetIsAFewSeconds() {
        let totalNanoseconds =
            UInt64(SignerHelperManager.postRegisterMaxAttempts) *
            SignerHelperManager.postRegisterPollInterval
        XCTAssertGreaterThanOrEqual(totalNanoseconds, 1_000_000_000)
        XCTAssertLessThanOrEqual(totalNanoseconds, 10_000_000_000)
    }

    // MARK: - isProtectionActive (FIX-3: green state gated on real readiness)

    /// "Protection Active" must be false whenever the helper is not ready, even
    /// if the sysext is activated and the filter is toggled on (the drill defect:
    /// a bare filter toggle read as fully protected with no helper/pin).
    func testProtectionNotActiveWhenNotReady() {
        XCTAssertFalse(
            SignerHelperManager.isProtectionActive(
                isReady: false,
                sysextActivated: true,
                filterEnabled: true
            )
        )
    }

    func testProtectionActiveRequiresAllThree() {
        XCTAssertTrue(
            SignerHelperManager.isProtectionActive(
                isReady: true,
                sysextActivated: true,
                filterEnabled: true
            )
        )
        XCTAssertFalse(
            SignerHelperManager.isProtectionActive(
                isReady: true,
                sysextActivated: false,
                filterEnabled: true
            )
        )
        XCTAssertFalse(
            SignerHelperManager.isProtectionActive(
                isReady: true,
                sysextActivated: true,
                filterEnabled: false
            )
        )
    }
}
