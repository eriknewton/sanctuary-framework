//
// FilterConfigurationManagerTests.swift
//
// Disarm state model. A disarm attempt is complete ONLY when a re-read proves
// the filter is off; every failure path (including the previously-swallowed
// loadFromPreferences error) must keep `disarmPending` set so the UI keeps a
// retryable Disarm control on screen. The model is a pure function
// (`disarmOutcome`) so these matrices run without
// NEFilterManager.
//

import XCTest
@testable import CastleWallHostApp

final class FilterConfigurationManagerTests: XCTestCase {

    // MARK: - Failure paths keep the disarm retryable

    /// A load error is a FAILED disarm attempt (nothing was saved): the
    /// filter state reflects the failure and the disarm stays pending.
    func testLoadFailureKeepsDisarmPendingAndReportsError() {
        let out = FilterConfigurationManager.disarmOutcome(.loadFailed("prefs unavailable"))
        XCTAssertTrue(out.disarmPending)
        guard case let .error(message) = out.filterState else {
            return XCTFail("expected .error, got \(out.filterState)")
        }
        XCTAssertTrue(message.contains("Disarm failed"))
        XCTAssertTrue(message.contains("prefs unavailable"))
    }

    /// The failed-save shape: saveToPreferences fails, the REAL filter may still
    /// be enabled. The state must reflect failure AND keep the disarm
    /// pending - never silently fall back to a state that hides the exit path.
    func testSaveFailureKeepsDisarmPendingAndReportsError() {
        let out = FilterConfigurationManager.disarmOutcome(.saveFailed("permission denied"))
        XCTAssertTrue(out.disarmPending)
        guard case let .error(message) = out.filterState else {
            return XCTFail("expected .error, got \(out.filterState)")
        }
        XCTAssertTrue(message.contains("permission denied"))
    }

    /// A save "success" with a failed verification re-read is NOT a verified
    /// disarm - the disable may not have taken effect.
    func testVerifyLoadFailureKeepsDisarmPending() {
        let out = FilterConfigurationManager.disarmOutcome(.verifyLoadFailed("read failed"))
        XCTAssertTrue(out.disarmPending)
        guard case let .error(message) = out.filterState else {
            return XCTFail("expected .error, got \(out.filterState)")
        }
        XCTAssertTrue(message.contains("Disarm unverified"))
    }

    /// The re-read proving the filter STILL enabled after a "successful" save
    /// is a failed disarm: pending stays set, the state says so.
    func testVerifiedStillEnabledKeepsDisarmPending() {
        let out = FilterConfigurationManager.disarmOutcome(.verified(filterStillEnabled: true))
        XCTAssertTrue(out.disarmPending)
        guard case let .error(message) = out.filterState else {
            return XCTFail("expected .error, got \(out.filterState)")
        }
        XCTAssertTrue(message.lowercased().contains("still enabled"))
    }

    // MARK: - The ONLY clearing path: verified-disabled

    func testVerifiedDisabledClearsDisarmPendingAndReadsDisabled() {
        let out = FilterConfigurationManager.disarmOutcome(.verified(filterStillEnabled: false))
        XCTAssertFalse(out.disarmPending)
        XCTAssertEqual(out.filterState, .disabled)
    }

    /// Exhaustive sweep: of every terminal event the disarm flow can end on,
    /// exactly one - verified-disabled - clears the pending latch.
    func testOnlyVerifiedDisabledClearsPending() {
        let events: [FilterConfigurationManager.DisarmAttemptEvent] = [
            .loadFailed("e"),
            .saveFailed("e"),
            .verifyLoadFailed("e"),
            .verified(filterStillEnabled: true),
            .verified(filterStillEnabled: false),
        ]
        let cleared = events.filter { !FilterConfigurationManager.disarmOutcome($0).disarmPending }
        XCTAssertEqual(cleared, [.verified(filterStillEnabled: false)])
    }
}
